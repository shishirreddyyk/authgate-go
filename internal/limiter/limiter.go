// Package limiter implements a sliding-window-counter rate limiter.
//
// The naive fixed window lets a caller send 2x the limit across a window
// boundary: full quota at 0:59, full quota again at 1:00. The sliding
// window counter fixes that by weighting the previous window's count by
// how much of it is still inside the trailing window. That boundary case
// has a test (TestSlidingWindowSurvivesBoundary) because it is the whole
// reason this is not a fixed window.
package limiter

import (
	"context"
	"math"
	"time"
)

// Store holds the per-key counters. Implementations must be safe for
// concurrent use.
type Store interface {
	// Incr counts one hit against key in the window containing now and
	// returns the current window's count and the previous window's count.
	Incr(ctx context.Context, key string, window time.Duration, now time.Time) (cur, prev int64, err error)
}

// Decision is the outcome of one Allow call.
type Decision struct {
	Allowed    bool
	Limit      int64
	Remaining  int64
	Estimate   float64
	RetryAfter time.Duration
}

type Limiter struct {
	store  Store
	limit  int64
	window time.Duration
}

func New(store Store, limit int64, window time.Duration) *Limiter {
	if limit < 1 {
		limit = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{store: store, limit: limit, window: window}
}

func (l *Limiter) Limit() int64          { return l.limit }
func (l *Limiter) Window() time.Duration { return l.window }

// Allow counts the request and reports whether it is within budget.
//
// The hit is counted even when it is rejected. That is deliberate: a
// caller hammering a limit should not get a free retry budget by being
// rejected, and it means an attacker cannot use 429s to probe the
// boundary for free.
func (l *Limiter) Allow(ctx context.Context, key string, now time.Time) (Decision, error) {
	cur, prev, err := l.store.Incr(ctx, key, l.window, now)
	if err != nil {
		return Decision{}, err
	}

	elapsed := now.Sub(now.Truncate(l.window))
	weight := 1 - (float64(elapsed) / float64(l.window))
	estimate := float64(prev)*weight + float64(cur)

	remaining := l.limit - int64(math.Ceil(estimate))
	if remaining < 0 {
		remaining = 0
	}

	retry := l.window - elapsed
	if retry < time.Second {
		retry = time.Second
	}

	return Decision{
		Allowed:    estimate <= float64(l.limit),
		Limit:      l.limit,
		Remaining:  remaining,
		Estimate:   estimate,
		RetryAfter: retry.Round(time.Second),
	}, nil
}
