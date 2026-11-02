package auth

import "time"

// SessionBindingSnapshot is one session-to-credential binding as written to disk, so a core that takes over
// from another (hot swap) or starts again keeps every session on its credential and its prompt cache warm.
type SessionBindingSnapshot struct {
	AuthID    string    `json:"auth_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Aliases   []string  `json:"aliases"`
	SessionID string    `json:"session_id,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Sequence  uint64    `json:"sequence,omitempty"`
}

// Snapshot returns the live bindings, oldest first.
func (c *SessionCache) Snapshot() []SessionBindingSnapshot {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.evictionOrder == nil {
		return nil
	}
	now := time.Now()
	out := make([]SessionBindingSnapshot, 0, len(c.groups))
	for elem := c.evictionOrder.Front(); elem != nil; elem = elem.Next() {
		key, _ := elem.Value.(string)
		entry, ok := c.groups[key]
		if !ok || !now.Before(entry.expiresAt) {
			continue
		}
		out = append(out, SessionBindingSnapshot{
			AuthID: entry.authID, ExpiresAt: entry.expiresAt, Aliases: append([]string(nil), entry.aliases...),
			SessionID: entry.binding.sessionID, Provider: entry.binding.provider, Sequence: entry.binding.sequence,
		})
	}
	return out
}

// Restore adds bindings from a snapshot, skipping expired ones and sessions this cache already binds.
func (c *SessionCache) Restore(items []SessionBindingSnapshot) int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	now, restored := time.Now(), 0
	for _, item := range items {
		aliases := compactSessionAliases(mergeSessionAliases(nil, item.Aliases...))
		if item.AuthID == "" || len(aliases) == 0 || !now.Before(item.ExpiresAt) {
			continue
		}
		if _, bound := c.entries[aliases[0]]; bound {
			continue
		}
		binding := sessionBinding{sessionID: item.SessionID, provider: item.Provider, sequence: item.Sequence}
		c.replaceAliasGroupsLocked(item.AuthID, item.ExpiresAt, aliases, binding)
		if item.Sequence > c.bindingSequence {
			c.bindingSequence = item.Sequence
		}
		restored++
	}
	return restored
}

// SessionBindings returns the selector's live session bindings.
func (s *SessionAffinitySelector) SessionBindings() []SessionBindingSnapshot {
	if s == nil {
		return nil
	}
	return s.cache.Snapshot()
}

// RestoreSessionBindings adds bindings saved by an earlier or handing-over core.
func (s *SessionAffinitySelector) RestoreSessionBindings(items []SessionBindingSnapshot) int {
	if s == nil {
		return 0
	}
	return s.cache.Restore(items)
}
