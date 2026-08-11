// Package abuse tracks failed authentication and puts noisy sources in
// a penalty box.
//
// The design decision worth arguing about: a block applies only to
// requests that fail to authenticate. A caller presenting a valid key
// from a penalized IP is still served. Blocking the whole address would
// mean one attacker behind a shared NAT can lock out every legitimate
// user on it, and the point of this control is to make credential
// guessing expensive, not to hand an attacker a denial-of-service
// primitive against their neighbours.
package abuse

import (
	"context"
	"sync"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/limiter"
)

type Config struct {
	// Threshold failures inside Window before the first block.
	Threshold int64
	Window    time.Duration
	// Base block duration, doubling per additional failure, capped at Max.
	Base time.Duration
	Max  time.Duration
}

func DefaultConfig() Config {
	return Config{
		Threshold: 5,
		Window:    time.Minute,
		Base:      30 * time.Second,
		Max:       15 * time.Minute,
	}
}

type Tracker struct {
	cfg   Config
	store limiter.Store

	mu      sync.Mutex
	blocked map[string]time.Time
}

func NewTracker(store limiter.Store, cfg Config) *Tracker {
	return &Tracker{cfg: cfg, store: store, blocked: make(map[string]time.Time)}
}

// RecordFailure counts one authentication failure for src and returns
// the time the source is blocked until (zero if it is not blocked).
//
// The counter goes through the shared store, so failures spread across
// replicas still add up. The resulting block is cached locally, which
// means a brand-new replica can be up to one window behind on an
// in-flight attacker. Named in DESIGN.md rather than hidden.
func (t *Tracker) RecordFailure(ctx context.Context, src string, now time.Time) (time.Time, error) {
	cur, _, err := t.store.Incr(ctx, "authfail:"+src, t.cfg.Window, now)
	if err != nil {
		return time.Time{}, err
	}
	if cur < t.cfg.Threshold {
		return time.Time{}, nil
	}

	over := cur - t.cfg.Threshold
	if over > 20 {
		over = 20 // guard the shift below
	}
	d := t.cfg.Base << uint(over)
	if d > t.cfg.Max || d <= 0 {
		d = t.cfg.Max
	}

	until := now.Add(d)
	t.mu.Lock()
	if existing, ok := t.blocked[src]; !ok || until.After(existing) {
		t.blocked[src] = until
	}
	t.mu.Unlock()

	return until, nil
}

// Blocked reports whether src is currently in the penalty box.
func (t *Tracker) Blocked(src string, now time.Time) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	until, ok := t.blocked[src]
	if !ok {
		return false, 0
	}
	if !now.Before(until) {
		delete(t.blocked, src)
		return false, 0
	}
	return true, until.Sub(now)
}

// Sweep clears expired blocks.
func (t *Tracker) Sweep(now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for src, until := range t.blocked {
		if !now.Before(until) {
			delete(t.blocked, src)
			n++
		}
	}
	return n
}
