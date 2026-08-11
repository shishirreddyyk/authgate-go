package abuse

import (
	"context"
	"testing"
	"time"

	"github.com/shishirreddyyk/authgate-go/internal/limiter"
)

func testTracker() *Tracker {
	return NewTracker(limiter.NewMemory(), Config{
		Threshold: 5,
		Window:    time.Minute,
		Base:      30 * time.Second,
		Max:       15 * time.Minute,
	})
}

func TestBlocksOnlyAfterThreshold(t *testing.T) {
	tr := testTracker()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	for i := 1; i < 5; i++ {
		until, err := tr.RecordFailure(ctx, "10.0.0.1", now)
		if err != nil {
			t.Fatal(err)
		}
		if !until.IsZero() {
			t.Fatalf("blocked after %d failures, threshold is 5", i)
		}
		if blocked, _ := tr.Blocked("10.0.0.1", now); blocked {
			t.Fatalf("source in penalty box after %d failures", i)
		}
	}

	until, err := tr.RecordFailure(ctx, "10.0.0.1", now)
	if err != nil {
		t.Fatal(err)
	}
	if until.IsZero() {
		t.Fatal("fifth failure did not trigger a block")
	}
	blocked, retry := tr.Blocked("10.0.0.1", now)
	if !blocked {
		t.Fatal("Blocked disagrees with RecordFailure")
	}
	if retry <= 0 {
		t.Fatal("block carried no remaining duration")
	}
}

func TestBlockEscalatesAndCaps(t *testing.T) {
	tr := testTracker()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	var first, second time.Time
	for i := 1; i <= 7; i++ {
		until, err := tr.RecordFailure(ctx, "10.0.0.2", now)
		if err != nil {
			t.Fatal(err)
		}
		if i == 5 {
			first = until
		}
		if i == 6 {
			second = until
		}
	}
	if !second.After(first) {
		t.Fatal("repeat offence did not extend the block")
	}

	for i := 0; i < 40; i++ {
		if _, err := tr.RecordFailure(ctx, "10.0.0.2", now); err != nil {
			t.Fatal(err)
		}
	}
	_, retry := tr.Blocked("10.0.0.2", now)
	if retry > 15*time.Minute {
		t.Fatalf("block ran to %s, past the 15m cap", retry)
	}
}

func TestBlockExpires(t *testing.T) {
	tr := testTracker()
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if _, err := tr.RecordFailure(ctx, "10.0.0.3", now); err != nil {
			t.Fatal(err)
		}
	}
	if blocked, _ := tr.Blocked("10.0.0.3", now); !blocked {
		t.Fatal("expected a block")
	}
	if blocked, _ := tr.Blocked("10.0.0.3", now.Add(31*time.Second)); blocked {
		t.Fatal("block outlived its duration")
	}
}

func TestSourcesAreTrackedIndependently(t *testing.T) {
	tr := testTracker()
	now := time.Now()
	ctx := context.Background()

	for i := 0; i < 6; i++ {
		if _, err := tr.RecordFailure(ctx, "10.0.0.4", now); err != nil {
			t.Fatal(err)
		}
	}
	if blocked, _ := tr.Blocked("10.0.0.5", now); blocked {
		t.Fatal("one noisy source blocked an unrelated address")
	}
}

func TestSweepClearsExpired(t *testing.T) {
	tr := testTracker()
	now := time.Now()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := tr.RecordFailure(ctx, "10.0.0.6", now); err != nil {
			t.Fatal(err)
		}
	}
	if n := tr.Sweep(now.Add(time.Hour)); n != 1 {
		t.Fatalf("swept %d, want 1", n)
	}
}
