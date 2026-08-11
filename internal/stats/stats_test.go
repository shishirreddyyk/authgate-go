package stats

import (
	"sync"
	"testing"
	"time"
)

func TestPercentilesOverKnownDistribution(t *testing.T) {
	r := NewRecorder()
	// 1ms .. 100ms, one sample each.
	for i := 1; i <= 100; i++ {
		r.Observe(time.Duration(i)*time.Millisecond, Allowed)
	}

	s := r.Snapshot()
	if s.Samples != 100 {
		t.Fatalf("samples = %d, want 100", s.Samples)
	}
	if s.P50ms != 50 {
		t.Fatalf("p50 = %v, want 50", s.P50ms)
	}
	if s.P95ms != 95 {
		t.Fatalf("p95 = %v, want 95", s.P95ms)
	}
	if s.P99ms != 99 {
		t.Fatalf("p99 = %v, want 99", s.P99ms)
	}
}

// TestPercentilesAreRealSamples: nearest-rank must return a value that
// was actually measured, never an interpolated number nobody observed.
func TestPercentilesAreRealSamples(t *testing.T) {
	r := NewRecorder()
	r.Observe(10*time.Millisecond, Allowed)
	r.Observe(20*time.Millisecond, Allowed)
	r.Observe(500*time.Millisecond, Allowed)

	s := r.Snapshot()
	for _, got := range []float64{s.P50ms, s.P95ms, s.P99ms} {
		if got != 10 && got != 20 && got != 500 {
			t.Fatalf("percentile %v was never measured", got)
		}
	}
	if s.P99ms != 500 {
		t.Fatalf("p99 = %v, want the slowest sample", s.P99ms)
	}
}

func TestOutcomesAreCountedSeparately(t *testing.T) {
	r := NewRecorder()
	r.Observe(time.Millisecond, Allowed)
	r.Observe(time.Millisecond, Allowed)
	r.Observe(time.Millisecond, RateLimited)
	r.Observe(time.Millisecond, Denied)

	s := r.Snapshot()
	if s.Total != 4 || s.Allowed != 2 || s.RateLimited != 1 || s.Denied != 1 {
		t.Fatalf("got %+v", s)
	}
}

// TestRingIsBounded: memory must not grow with traffic.
func TestRingIsBounded(t *testing.T) {
	r := NewRecorder()
	for i := 0; i < ringSize*3; i++ {
		r.Observe(time.Millisecond, Allowed)
	}
	s := r.Snapshot()
	if s.Samples != ringSize {
		t.Fatalf("kept %d samples, want the ring capped at %d", s.Samples, ringSize)
	}
	if s.Total != uint64(ringSize*3) {
		t.Fatalf("total = %d, want every request counted even though samples are capped", s.Total)
	}
}

func TestEmptySnapshotDoesNotPanic(t *testing.T) {
	s := NewRecorder().Snapshot()
	if s.Total != 0 || s.P99ms != 0 {
		t.Fatalf("got %+v", s)
	}
}

func TestConcurrentObservers(t *testing.T) {
	r := NewRecorder()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.Observe(time.Millisecond, Allowed)
			}
		}()
	}
	wg.Wait()
	if got := r.Snapshot().Total; got != 2000 {
		t.Fatalf("total = %d, want 2000", got)
	}
}
