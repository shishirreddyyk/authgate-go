package limiter

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/resp"
)

// Memory is a single-process counter store. Correct for one instance,
// wrong the moment you run two: each replica would enforce its own
// budget. It is the default only so the service runs with no Redis.
type Memory struct {
	mu      sync.Mutex
	entries map[string]*memEntry
}

type memEntry struct {
	windowStart time.Time
	cur         int64
	prev        int64
}

func NewMemory() *Memory {
	return &Memory{entries: make(map[string]*memEntry)}
}

func (m *Memory) Incr(_ context.Context, key string, window time.Duration, now time.Time) (int64, int64, error) {
	start := now.Truncate(window)

	m.mu.Lock()
	defer m.mu.Unlock()

	e, ok := m.entries[key]
	if !ok {
		m.entries[key] = &memEntry{windowStart: start, cur: 1}
		return 1, 0, nil
	}

	switch {
	case e.windowStart.Equal(start):
		e.cur++
	case e.windowStart.Equal(start.Add(-window)):
		e.prev, e.cur, e.windowStart = e.cur, 1, start
	default:
		// Gap longer than one window: nothing carries over.
		e.prev, e.cur, e.windowStart = 0, 1, start
	}
	return e.cur, e.prev, nil
}

// Sweep drops entries that have not been touched for two windows. Call
// it periodically or a long-lived process leaks one map entry per key.
func (m *Memory) Sweep(window time.Duration, now time.Time) int {
	cutoff := now.Add(-2 * window)
	removed := 0

	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.entries {
		if e.windowStart.Before(cutoff) {
			delete(m.entries, k)
			removed++
		}
	}
	return removed
}

// incrScript increments the current window and reads the previous one in
// a single round trip. It has to be atomic: read-then-write from the
// service would let two concurrent requests both observe count N and
// both write N+1, which is exactly the race an attacker with parallel
// connections would exploit.
const incrScript = `
local cur_key  = KEYS[1]
local prev_key = KEYS[2]
local ttl_ms   = tonumber(ARGV[1])
local cur = redis.call('INCR', cur_key)
redis.call('PEXPIRE', cur_key, ttl_ms)
local prev = redis.call('GET', prev_key)
if not prev then prev = 0 end
return {cur, tonumber(prev)}
`

// Redis is a shared counter store. Every replica enforces one budget.
type Redis struct {
	client *resp.Client
	prefix string
}

func NewRedis(client *resp.Client, prefix string) *Redis {
	if prefix == "" {
		prefix = "authgate"
	}
	return &Redis{client: client, prefix: prefix}
}

func (r *Redis) Incr(_ context.Context, key string, window time.Duration, now time.Time) (int64, int64, error) {
	windowMS := window.Milliseconds()
	if windowMS <= 0 {
		windowMS = 1
	}
	start := now.Truncate(window).UnixMilli()

	curKey := fmt.Sprintf("%s:%s:%d", r.prefix, key, start)
	prevKey := fmt.Sprintf("%s:%s:%d", r.prefix, key, start-windowMS)
	ttl := strconv.FormatInt(windowMS*2, 10)

	v, err := r.client.Do("EVAL", incrScript, "2", curKey, prevKey, ttl)
	if err != nil {
		return 0, 0, err
	}
	if v.Kind != resp.KindArray || len(v.Array) != 2 {
		return 0, 0, fmt.Errorf("limiter: unexpected reply shape from redis")
	}
	return v.Array[0].Int, v.Array[1].Int, nil
}
