package cliproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
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
// The opener reads each Claude account's usage (Anthropic's usage endpoint, which costs no tokens) and,
// when an account has no open 5-hour window, sends it one tiny message, so a new window starts right away.
// Accounts with a weekly cap are opened only while their weekly utilization is under the ceiling for
// their plan: a window on an account whose week is nearly spent buys nothing.
//
// The usage endpoint is rate limited, so an account is read again only when its state can have changed:
// an open window at its reset, an account over its ceiling or without a 5-hour limit after a long pause,
// and after a refusal no sooner than Anthropic's Retry-After.

const (
	claudeUsageURL   = "https://api.anthropic.com/api/oauth/usage"
	claudeProfileURL = "https://api.anthropic.com/api/oauth/profile"
	claudeOAuthBeta  = "oauth-2025-04-20"

	// windowOpenerDefaultInterval is how often the opener looks for accounts that are due; only due accounts
	// are read.
	windowOpenerDefaultInterval = time.Minute
	windowOpenerDefaultModel    = "claude-haiku-5-5"
	windowOpenerDefaultPrompt   = "Respond with zoo7"
	// windowOpenerAfterReset is how long after a window's reset time it is read again, so the reset has
	// happened by then.
	windowOpenerAfterReset = 30 * time.Second
	// windowOpenerConfirm is when an account is read again after an opening message, to see the new window.
	windowOpenerConfirm = 2 * time.Minute
	// windowOpenerIdle is the pause for a state only use or a weekly reset changes: over the weekly ceiling,
	// or no 5-hour limit. Real traffic on the account opens its window by itself meanwhile.
	windowOpenerIdle = 30 * time.Minute
	// windowOpenerFailed is the pause after an error with no Retry-After, and after a failed opening.
	windowOpenerFailed = 10 * time.Minute
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

// claudeOAuthError is a refused call to an account endpoint; retryAfter is Anthropic's Retry-After, if any.
type claudeOAuthError struct {
	status     int
	body       string
	retryAfter time.Duration
}

func (e *claudeOAuthError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }

// windowOpenerAccount is what the opener remembers about one credential between checks.
type windowOpenerAccount struct {
	plan        string
	planFetched time.Time
	nextCheck   time.Time // the account is not read before this
	lastState   string    // the last decision logged, so a steady state is logged once
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

// runWindowOpener checks the due Claude accounts once per interval while the opener is enabled. The
// settings are read on every round, so a config reload takes effect without a restart.
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
			if account := s.windowOpener.account(auth.ID); !time.Now().Before(account.nextCheck) {
				account.nextCheck = time.Now().Add(s.checkWindow(ctx, cfg, auth, account))
			}
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

// checkWindow opens the account's 5-hour window when it has none and its plan's weekly ceiling allows. It
// returns how long to wait before reading this account again.
func (s *Service) checkWindow(ctx context.Context, cfg *config.Config, auth *coreauth.Auth, account *windowOpenerAccount) time.Duration {
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
	refused := func(what string, err error) time.Duration {
		wait := windowOpenerFailed
		var oauthErr *claudeOAuthError
		if errors.As(err, &oauthErr) && oauthErr.retryAfter > 0 {
			wait = oauthErr.retryAfter
		}
		note(what+" unknown (%v); next try in %s", err, wait.Round(time.Second))
		return wait
	}

	if account.plan == "" || time.Since(account.planFetched) > windowOpenerProfileTTL {
		var profile claudeProfile
		if err := s.claudeOAuthGet(ctx, cfg, auth, claudeProfileURL, &profile); err != nil {
			return refused("plan", err)
		}
		account.plan, account.planFetched = profile.Organization.OrganizationType, time.Now()
	}
	var usage claudeUsage
	if err := s.claudeOAuthGet(ctx, cfg, auth, claudeUsageURL, &usage); err != nil {
		return refused("usage", err)
	}
	now := time.Now()
	switch {
	case usage.FiveHour == nil:
		note("no 5-hour limit on this account (%s)", account.plan)
		return windowOpenerIdle
	case usage.FiveHour.ResetsAt != nil && usage.FiveHour.ResetsAt.After(now):
		note("window open until %s", usage.FiveHour.ResetsAt.Local().Format("15:04"))
		return usage.FiveHour.ResetsAt.Sub(now) + windowOpenerAfterReset
	}
	ceiling, capped := windowOpenerCeiling(cfg, account.plan)
	if capped && usage.SevenDay != nil && usage.SevenDay.Utilization >= ceiling {
		note("window closed, not opened: weekly %.0f%% is at or over the %s ceiling %.0f%%",
			usage.SevenDay.Utilization, account.plan, ceiling)
		return windowOpenerIdle
	}
	account.lastState = ""
	if err := s.openWindow(ctx, cfg, auth); err != nil {
		log.Warnf("window opener: %s: opening failed: %v", name, err)
		return windowOpenerFailed
	}
	log.Infof("window opener: %s: window opened (%s)", name, account.plan)
	return windowOpenerConfirm
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

// claudeOAuthGet reads one of Anthropic's OAuth account endpoints with the credential's token, once.
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
		e := &claudeOAuthError{status: resp.StatusCode, body: strings.TrimSpace(string(raw[:min(len(raw), 200)]))}
		if secs, errParse := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); errParse == nil && secs > 0 {
			e.retryAfter = time.Duration(secs) * time.Second
		}
		return e
	}
	return json.Unmarshal(raw, out)
}
