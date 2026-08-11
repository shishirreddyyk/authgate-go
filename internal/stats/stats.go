// Package stats records request latency and outcome counts.
//
// Percentiles come from a bounded ring of the most recent samples, so
// memory is fixed and the numbers describe recent behaviour rather than
// an average smeared over the whole process lifetime. p99 over all time
// is not an operationally useful number.
package stats

import (
	"sort"
	"sync"
	"time"
)

const ringSize = 4096

type Recorder struct {
	mu      sync.Mutex
	ring    [ringSize]time.Duration
	n       int // samples written, may exceed ringSize
	total   uint64
	allowed uint64
	limited uint64
	denied  uint64
}

func NewRecorder() *Recorder { return &Recorder{} }

type Outcome int

const (
	Allowed Outcome = iota
	RateLimited
	Denied
)

func (r *Recorder) Observe(d time.Duration, o Outcome) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.ring[r.n%ringSize] = d
	r.n++
	r.total++

	switch o {
	case Allowed:
		r.allowed++
	case RateLimited:
		r.limited++
	case Denied:
		r.denied++
	}
}

type Snapshot struct {
	Total       uint64  `json:"total_requests"`
	Allowed     uint64  `json:"allowed"`
	RateLimited uint64  `json:"rate_limited"`
	Denied      uint64  `json:"denied"`
	Samples     int     `json:"latency_samples"`
	P50ms       float64 `json:"p50_ms"`
	P95ms       float64 `json:"p95_ms"`
	P99ms       float64 `json:"p99_ms"`
}

func (r *Recorder) Snapshot() Snapshot {
	r.mu.Lock()
	size := r.n
	if size > ringSize {
		size = ringSize
	}
	samples := make([]time.Duration, size)
	copy(samples, r.ring[:size])
	s := Snapshot{
		Total:       r.total,
		Allowed:     r.allowed,
		RateLimited: r.limited,
		Denied:      r.denied,
		Samples:     size,
	}
	r.mu.Unlock()

	if size == 0 {
		return s
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	s.P50ms = ms(percentile(samples, 0.50))
	s.P95ms = ms(percentile(samples, 0.95))
	s.P99ms = ms(percentile(samples, 0.99))
	return s
}

// percentile uses nearest-rank, which is the definition that does not
// invent a value that was never measured.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted))+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}
