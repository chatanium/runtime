package http

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type bucket struct {
	refs      int
	busy      bool
	remaining int64
	known     bool
	reset     time.Time
	touched   time.Time
}

// reserve changes owner, host and bucket counters together or not at all.
// Waiting on a saturated request quota never reserves partial capacity. Bucket
// records with any waiting/active reference or live limit state cannot evict.
func (t *Transport) reserve(ctx context.Context, owner, key string) (*bucket, error) {
	for {
		if ctx.Err() != nil {
			return nil, t.failure(ctx, ErrTransport)
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return nil, ErrClosed
		}
		if t.active < t.config.RequestsPerHost && t.owners[owner] < t.config.RequestsPerInstance {
			now := time.Now()
			b := t.buckets[key]
			if b == nil {
				if len(t.buckets) >= t.config.RateLimitBuckets {
					for existing, state := range t.buckets {
						if state.refs == 0 && !state.busy && !now.Before(state.reset) && !now.Before(state.touched.Add(t.config.RateLimitRetention)) {
							delete(t.buckets, existing)
						}
					}
				}
				if len(t.buckets) >= t.config.RateLimitBuckets {
					t.mu.Unlock()
					return nil, ErrCapacity
				}
				b = &bucket{touched: now}
				t.buckets[key] = b
			}
			b.refs++
			t.active++
			t.owners[owner]++
			t.mu.Unlock()
			return b, nil
		}
		changed := t.changed
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, t.failure(ctx, ErrTransport)
		case <-changed:
		}
	}
}

func (t *Transport) release(owner string, b *bucket, admitted bool) {
	t.mu.Lock()
	b.refs--
	if admitted {
		b.busy = false
	}
	b.touched = time.Now()
	t.active--
	t.owners[owner]--
	if t.owners[owner] == 0 {
		delete(t.owners, owner)
	}
	t.signalLocked()
	t.mu.Unlock()
}

func (t *Transport) admit(ctx context.Context, b *bucket) error {
	for {
		if ctx.Err() != nil {
			return t.failure(ctx, ErrTransport)
		}
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return ErrClosed
		}
		now := time.Now()
		until := t.globalUntil
		if b.known && b.remaining == 0 && b.reset.After(until) {
			until = b.reset
		}
		if !b.busy && !until.After(now) {
			b.busy = true
			if b.known {
				if !now.Before(b.reset) {
					b.known = false
				} else if b.remaining > 0 {
					b.remaining--
				}
			}
			t.mu.Unlock()
			return nil
		}
		changed := t.changed
		t.mu.Unlock()
		if until.After(now) {
			timer := time.NewTimer(until.Sub(now))
			select {
			case <-ctx.Done():
				timer.Stop()
				return t.failure(ctx, ErrTransport)
			case <-changed:
				timer.Stop()
			case <-timer.C:
			}
		} else {
			select {
			case <-ctx.Done():
				return t.failure(ctx, ErrTransport)
			case <-changed:
			}
		}
	}
}

func secondsDuration(value string) (time.Duration, bool) {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds >= float64(math.MaxInt64)/float64(time.Second) {
		return 0, false
	}
	nanos := math.Ceil(seconds * float64(time.Second))
	if nanos >= float64(math.MaxInt64) {
		return 0, false
	}
	return time.Duration(nanos), true
}

func retryDuration(value string, now time.Time) (time.Duration, bool) {
	if duration, ok := secondsDuration(value); ok {
		return duration, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	if !when.After(now) {
		return 0, true
	}
	return when.Sub(now), true
}

// update never retries the completed request. It publishes only future
// admission state, retaining global 429s even if that route has no more calls.
func (t *Transport) update(b *bucket, status int, header http.Header, body []byte) {
	now := time.Now()
	delay, hasReset := secondsDuration(header.Get("X-RateLimit-Reset-After"))
	if !hasReset {
		if reset, err := strconv.ParseFloat(header.Get("X-RateLimit-Reset"), 64); err == nil && !math.IsNaN(reset) && !math.IsInf(reset, 0) && reset >= 0 && reset < float64(math.MaxInt64)/float64(time.Second) {
			serverNow := now
			if date, err := http.ParseTime(header.Get("Date")); err == nil {
				serverNow = date
			}
			seconds := reset - float64(serverNow.UnixNano())/float64(time.Second)
			if seconds < 0 {
				seconds = 0
			}
			delay, hasReset = secondsDuration(strconv.FormatFloat(seconds, 'g', -1, 64))
		}
	}
	remaining, remainingErr := strconv.ParseInt(header.Get("X-RateLimit-Remaining"), 10, 64)
	global := strings.EqualFold(header.Get("X-RateLimit-Global"), "true") || strings.EqualFold(header.Get("X-RateLimit-Scope"), "global")
	if status == http.StatusTooManyRequests {
		if retry, ok := retryDuration(header.Get("Retry-After"), now); ok {
			delay, hasReset = retry, true
		}
		var limited struct {
			RetryAfter json.Number `json:"retry_after"`
			Global     bool        `json:"global"`
		}
		if len(body) > 0 && json.Unmarshal(body, &limited) == nil {
			global = global || limited.Global
			if retry, ok := secondsDuration(string(limited.RetryAfter)); ok {
				delay, hasReset = retry, true
			}
		}
		remaining, remainingErr = 0, nil
	}
	t.mu.Lock()
	if remainingErr == nil && remaining >= 0 {
		b.remaining = remaining
		b.known = true
	}
	if hasReset {
		until := now.Add(delay)
		if status == http.StatusTooManyRequests && global {
			if until.After(t.globalUntil) {
				t.globalUntil = until
			}
		} else if until.After(b.reset) {
			b.reset = until
		}
	}
	b.touched = now
	t.signalLocked()
	t.mu.Unlock()
}
