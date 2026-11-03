package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// Window opener: a Claude subscription's 5-hour window starts at the first request after the previous one
// reset. An account nobody uses for a while starts its next window late, at whatever moment work arrives.
// The opener checks every Claude account's usage (Anthropic's usage endpoint, which costs nothing) and,
// when an account has no open 5-hour window, sends it one tiny message, so a new window starts right away.
// Accounts with a weekly cap are opened only while their weekly utilization is under the ceiling for
// their plan: a window on an account whose week is nearly spent buys nothing.

const (
	claudeUsageURL   = "https://api.anthropic.com/api/oauth/usage"
	claudeProfileURL = "https://api.anthropic.com/api/oauth/profile"
	claudeOAuthBeta  = "oauth-2025-04-20"

	windowOpenerDefaultInterval = time.Minute
	windowOpenerDefaultModel    = "claude-haiku-5-5"
	windowOpenerDefaultPrompt   = "Respond with zoo7"
	// windowOpenerRetryAfter spaces attempts on one account, so an opening the usage endpoint does not show
	// yet, or one that failed, is not repeated every check.
	windowOpenerRetryAfter = 5 * time.Minute
	// windowOpenerProfileTTL is how long an account's plan is cached.
	windowOpenerProfileTTL = 24 * time.Hour
)

var windowOpenerDefaultCeiling = map[string]float64{"claude_pro": 70, "claude_max": 80}

type claudeUsageWindow struct {
	Utilization float64    `json:"utilization"`
	ResetsAt    *time.Time `json:"resets_at"`
}

type claudeUsage struct {
	FiveHour *claudeUsageWindow `json:"five_hour"`
	SevenDay *claudeUsageWindow `json:"seven_day"`
}

type claudeProfile struct {
	Organization struct {
		OrganizationType string `json:"organization_type"`
	} `json:"organization"`
}

// windowOpenerAccount is what the opener remembers about one credential between checks.
type windowOpenerAccount struct {
	plan        string
	planFetched time.Time
	lastAttempt time.Time
	lastState   string // the last decision logged, so a steady state is logged once
}

type windowOpener struct {
	mu       sync.Mutex
	accounts map[string]*windowOpenerAccount
}

func (o *windowOpener) account(id string) *windowOpenerAccount {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.accounts == nil {
		o.accounts = make(map[string]*windowOpenerAccount)
	}
	a, ok := o.accounts[id]
	if !ok {
		a = &windowOpenerAccount{}
		o.accounts[id] = a
	}
	return a
}

// runWindowOpener checks all Claude accounts once per interval while the opener is enabled. The settings
// are read on every round, so a config reload takes effect without a restart.
func (s *Service) runWindowOpener(ctx context.Context) {
	for {
		cfg := s.currentConfig()
		interval := windowOpenerDefaultInterval
		if cfg != nil {
			if d, err := time.ParseDuration(cfg.Routing.WindowOpener.Interval); err == nil && d > 0 {
				interval = d
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		if cfg = s.currentConfig(); cfg == nil || !cfg.Routing.WindowOpener.Enabled || s.handingOver() {
			continue
		}
		for _, auth := range s.claudeOAuthAccounts() {
			s.checkWindow(ctx, cfg, auth)
		}
	}
}

// handingOver reports whether this core is giving way to another one; the new core runs the opener then.
func (s *Service) handingOver() bool {
	s.handover.mu.Lock()
	defer s.handover.mu.Unlock()
	return s.handover.prepared || s.handover.draining
}

func (s *Service) claudeOAuthAccounts() []*coreauth.Auth {
	if s.coreManager == nil {
		return nil
	}
	var out []*coreauth.Auth
	for _, auth := range s.coreManager.List() {
		if strings.EqualFold(auth.Provider, "claude") && !auth.Disabled && claudeAccessToken(auth) != "" {
			out = append(out, auth)
		}
	}
	return out
}

func claudeAccessToken(auth *coreauth.Auth) string {
	token, _ := auth.Metadata["access_token"].(string)
	return strings.TrimSpace(token)
}

// checkWindow opens the account's 5-hour window when it has none and its plan's weekly ceiling allows.
func (s *Service) checkWindow(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) {
	account := s.windowOpener.account(auth.ID)
	name := auth.Label
	if name == "" {
		name = auth.ID
	}
	note := func(state string, args ...any) {
		if state != account.lastState {
			account.lastState = state
			log.Infof("window opener: %s: "+state, append([]any{name}, args...)...)
		}
	}

	if account.plan == "" || time.Since(account.planFetched) > windowOpenerProfileTTL {
		var profile claudeProfile
		if err := s.claudeOAuthGet(ctx, cfg, auth, claudeProfileURL, &profile); err != nil {
			note("plan unknown (%v)", err)
			return
		}
		account.plan, account.planFetched = profile.Organization.OrganizationType, time.Now()
	}
	var usage claudeUsage
	if err := s.claudeOAuthGet(ctx, cfg, auth, claudeUsageURL, &usage); err != nil {
		note("usage unknown (%v)", err)
		return
	}
	now := time.Now()
	switch {
	case usage.FiveHour == nil:
		note("no 5-hour limit on this account (%s)", account.plan)
		return
	case usage.FiveHour.ResetsAt != nil && usage.FiveHour.ResetsAt.After(now):
		note("window open")
		return
	}
	ceiling, capped := windowOpenerCeiling(cfg, account.plan)
	if capped && usage.SevenDay != nil && usage.SevenDay.Utilization >= ceiling {
		note("window closed, not opened: weekly %.0f%% is at or over the %s ceiling %.0f%%",
			usage.SevenDay.Utilization, account.plan, ceiling)
		return
	}
	if now.Sub(account.lastAttempt) < windowOpenerRetryAfter {
		return
	}
	account.lastAttempt = now
	if err := s.openWindow(ctx, cfg, auth); err != nil {
		account.lastState = ""
		log.Warnf("window opener: %s: opening failed: %v", name, err)
		return
	}
	account.lastState = ""
	log.Infof("window opener: %s: window opened (%s)", name, account.plan)
}

func windowOpenerCeiling(cfg *config.Config, plan string) (float64, bool) {
	ceilings := cfg.Routing.WindowOpener.WeeklyCeiling
	if ceilings == nil {
		ceilings = windowOpenerDefaultCeiling
	}
	c, ok := ceilings[plan]
	return c, ok
}

// openWindow sends the opening message on this credential alone, through the same path as a client's request.
func (s *Service) openWindow(ctx context.Context, cfg *config.Config, auth *coreauth.Auth) error {
	if s.server == nil || s.server.ModelExecutor() == nil {
		return fmt.Errorf("model executor unavailable")
	}
	model := cfg.Routing.WindowOpener.Model
	if model == "" {
		model = windowOpenerDefaultModel
	}
	prompt := cfg.Routing.WindowOpener.Prompt
	if prompt == "" {
		prompt = windowOpenerDefaultPrompt
	}
	body, err := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 16,
		"messages":   []map[string]any{{"role": "user", "content": prompt}},
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	_, errMsg := s.server.ModelExecutor().ExecuteModel(ctx, handlers.ModelExecutionRequest{
		EntryProtocol: "claude",
		ExitProtocol:  "claude",
		Model:         model,
		Body:          body,
		AuthID:        auth.ID,
	})
	if errMsg != nil {
		return fmt.Errorf("%d: %v", errMsg.StatusCode, errMsg.Error)
	}
	return nil
}

// claudeOAuthGet reads one of Anthropic's OAuth account endpoints with the credential's token.
func (s *Service) claudeOAuthGet(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, url string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+claudeAccessToken(auth))
	req.Header.Set("anthropic-beta", claudeOAuthBeta)
	resp, err := helps.NewProxyAwareHTTPClient(ctx, cfg, auth, 20*time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw[:min(len(raw), 200)])))
	}
	return json.Unmarshal(raw, out)
}
