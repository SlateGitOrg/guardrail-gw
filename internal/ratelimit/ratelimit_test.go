package ratelimit

import (
	"sync"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestBurstThenRefill(t *testing.T) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	l := NewWithClock(c.now)
	r := Rate{PerMinute: 60, Burst: 3}
	for i := 0; i < 3; i++ {
		if d := l.Allow("a", r); !d.Allowed || d.Remaining != 2-i {
			t.Fatalf("request %d: %+v", i, d)
		}
	}
	d := l.Allow("a", r)
	if d.Allowed || d.RetryAfter <= 0 || d.RetryAfter > time.Second {
		t.Fatalf("expected deny with ~1s retry, got %+v", d)
	}
	c.advance(time.Second)
	if !l.Allow("a", r).Allowed {
		t.Fatal("expected refill after 1s")
	}
	// Keys are independent.
	if !l.Allow("b", r).Allowed {
		t.Fatal("key b should have its own bucket")
	}
}

func TestRateChangeClampsBurst(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := NewWithClock(c.now)
	l.Allow("a", Rate{PerMinute: 600, Burst: 100})
	// Reload lowers the burst; the bucket must not keep 99 tokens.
	small := Rate{PerMinute: 60, Burst: 2}
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("a", small).Allowed {
			allowed++
		}
	}
	if allowed != 2 {
		t.Fatalf("allowed %d after burst reduced to 2", allowed)
	}
}

func TestForgetAndConcurrency(t *testing.T) {
	l := New()
	r := Rate{PerMinute: 1, Burst: 50}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Allow("k", r).Allowed {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 50 {
		t.Fatalf("allowed %d, want exactly burst=50", ok)
	}
	l.Forget(func(string) bool { return false })
	if !l.Allow("k", r).Allowed {
		t.Fatal("forgotten key should start with a full bucket")
	}
}
