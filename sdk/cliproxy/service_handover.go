package cliproxy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// Hot swap of the core, without cutting requests:
//  1. the old core is told to prepare: it saves its session bindings and stops refreshing tokens, so the two
//     cores never rotate the same refresh token;
//  2. the new core starts, loads the bindings and binds the same port (SO_REUSEPORT);
//  3. the old core is told to drain: it stops accepting, finishes the requests in flight, then exits.
// The bindings are also saved every few seconds, so a restart keeps sessions on their credentials too.

const (
	sessionBindingsFile         = "session-affinity.json"
	sessionBindingsSaveInterval = 10 * time.Second
)

type handoverState struct {
	mu        sync.Mutex
	prepared  bool // told to prepare: a new core takes over
	draining  bool
	drainDone chan struct{}
	lastSaved []coreauth.SessionBindingSnapshot
}

func (s *Service) sessionBindingsPath() string {
	if s.configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.configPath), sessionBindingsFile)
}

func (s *Service) affinitySelector() *coreauth.SessionAffinitySelector {
	if s.coreManager == nil {
		return nil
	}
	selector, _ := s.coreManager.Selector().(*coreauth.SessionAffinitySelector)
	return selector
}

// restoreSessionBindings loads the bindings saved by the previous or handing-over core.
func (s *Service) restoreSessionBindings() {
	path, selector := s.sessionBindingsPath(), s.affinitySelector()
	if path == "" || selector == nil {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("session bindings: read %s: %v", path, err)
		}
		return
	}
	var items []coreauth.SessionBindingSnapshot
	if err := json.Unmarshal(raw, &items); err != nil {
		log.Warnf("session bindings: parse %s: %v", path, err)
		return
	}
	log.Infof("session bindings: restored %d of %d from %s", selector.RestoreSessionBindings(items), len(items), path)
}

// saveSessionBindings writes the current bindings when they changed since the last write.
func (s *Service) saveSessionBindings() {
	path, selector := s.sessionBindingsPath(), s.affinitySelector()
	if path == "" || selector == nil {
		return
	}
	items := selector.SessionBindings()
	s.handover.mu.Lock()
	defer s.handover.mu.Unlock()
	if reflect.DeepEqual(items, s.handover.lastSaved) {
		return
	}
	raw, err := json.Marshal(items)
	if err != nil {
		log.Warnf("session bindings: encode: %v", err)
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Warnf("session bindings: write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Warnf("session bindings: rename %s: %v", tmp, err)
		return
	}
	s.handover.lastSaved = items
}

func (s *Service) saveSessionBindingsEvery(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.handover.mu.Lock()
			draining := s.handover.draining
			s.handover.mu.Unlock()
			if !draining { // once draining, the new core owns the file
				s.saveSessionBindings()
			}
		}
	}
}

// PrepareHandover is step 1 of a hot swap: save the bindings for the new core and stop refreshing tokens
// and opening windows.
func (s *Service) PrepareHandover() {
	if s == nil {
		return
	}
	s.handover.mu.Lock()
	s.handover.prepared = true
	s.handover.mu.Unlock()
	s.saveSessionBindings()
	if s.coreManager != nil {
		s.coreManager.StopAutoRefresh()
	}
	log.Info("hot swap: bindings saved, token refresh stopped; waiting for the drain signal")
}

// Drain is step 3 of a hot swap: stop accepting, finish the requests in flight (at most timeout), then return.
// The caller ends the service afterwards.
func (s *Service) Drain(timeout time.Duration) {
	if s == nil || s.server == nil {
		return
	}
	s.handover.mu.Lock()
	if s.handover.draining {
		s.handover.mu.Unlock()
		return
	}
	s.handover.draining = true
	s.handover.drainDone = make(chan struct{})
	done := s.handover.drainDone
	s.handover.mu.Unlock()
	defer close(done)

	if s.coreManager != nil {
		s.coreManager.StopAutoRefresh()
	}
	log.Infof("hot swap: draining; no new connections, waiting up to %s for requests in flight", timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.server.Drain(ctx); err != nil {
		log.Warnf("hot swap: drain ended before all requests finished: %v", err)
		return
	}
	log.Info("hot swap: all requests finished")
}

// waitForDrain blocks while a drain is running, so the service does not close connections still in use.
func (s *Service) waitForDrain() {
	s.handover.mu.Lock()
	done := s.handover.drainDone
	s.handover.mu.Unlock()
	if done != nil {
		<-done
	}
}
