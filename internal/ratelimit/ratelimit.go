// Package ratelimit implements per-key token buckets.
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Rate is a sustained rate plus a burst capacity.
type Rate struct {
	PerMinute float64
	Burst     int
}

// Decision is the outcome of Allow.
type Decision struct {
	Allowed    bool
	Remaining  int           // whole tokens left after this request
	RetryAfter time.Duration // when Allowed is false: wait before retrying
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter holds one bucket per key name. Buckets refill lazily, so an idle
// key costs nothing. Rates may change between calls (config hot reload); a
// bucket is clamped to the new burst on its next use.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time
}

// New returns a Limiter using the wall clock.
func New() *Limiter { return NewWithClock(time.Now) }

// NewWithClock returns a Limiter with an injectable clock (for tests).
func NewWithClock(now func() time.Time) *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, now: now}
}

// Allow takes one token from key's bucket if available.
func (l *Limiter) Allow(key string, r Rate) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	capacity := float64(r.Burst)
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: capacity, last: now}
		l.buckets[key] = b
	}
	perSec := r.PerMinute / 60
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * perSec
	}
	b.tokens = math.Min(b.tokens, capacity)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return Decision{Allowed: true, Remaining: int(b.tokens)}
	}
	wait := time.Duration((1 - b.tokens) / perSec * float64(time.Second))
	return Decision{Allowed: false, RetryAfter: wait}
}

// Forget drops buckets for keys not in keep (called after a reload removes keys).
func (l *Limiter) Forget(keep func(key string) bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.buckets {
		if !keep(k) {
			delete(l.buckets, k)
		}
	}
}
