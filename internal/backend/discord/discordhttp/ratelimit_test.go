package discordhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionCancellationDoesNotUnlockAnotherRequest(t *testing.T) {
	transport := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) { return successResponse(), nil })
	first, err := transport.reserve(context.Background(), "owner", "bucket")
	if err != nil {
		t.Fatal(err)
	}
	if err = transport.admit(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second, err := transport.reserve(context.Background(), "owner", "bucket")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = transport.admit(ctx, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting cancellation: %v", err)
	}
	transport.release("owner", second, false)
	transport.mu.Lock()
	busy, active, refs := first.busy, transport.active, first.refs
	transport.mu.Unlock()
	if !busy || active != 1 || refs != 1 {
		t.Fatalf("canceled waiter altered live owner busy=%v active=%d refs=%d", busy, active, refs)
	}
	transport.release("owner", first, true)
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.active != 0 || len(transport.owners) != 0 || first.refs != 0 || first.busy {
		t.Fatal("slot counters did not return exactly once")
	}
}

func TestSlotReservationIsAtomicAndCanceledWaitAddsNoRecords(t *testing.T) {
	config := testConfig()
	config.RequestsPerInstance = 1
	config.RequestsPerHost = 1
	transport := newTestTransport(t, config, func(*http.Request) (*http.Response, error) { return successResponse(), nil })
	first, err := transport.reserve(context.Background(), "first", "first")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := transport.reserve(ctx, "second", "second"); done <- err }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	transport.mu.Lock()
	if transport.active != 1 || len(transport.owners) != 1 || len(transport.buckets) != 1 {
		t.Error("slot wait retained a partial owner/bucket reservation")
	}
	transport.mu.Unlock()
	transport.release("first", first, false)
}

func TestBucketCapacityRetainsLiveWaitAndLimitState(t *testing.T) {
	config := testConfig()
	config.RateLimitBuckets = 1
	transport := newTestTransport(t, config, func(*http.Request) (*http.Response, error) { return successResponse(), nil })
	first, err := transport.reserve(context.Background(), "owner", "one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.reserve(context.Background(), "other", "two"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("live record evicted: %v", err)
	}
	transport.release("owner", first, false)
	transport.mu.Lock()
	first.touched = time.Now().Add(-2 * config.RateLimitRetention)
	first.reset = time.Now().Add(time.Hour)
	transport.mu.Unlock()
	if _, err = transport.reserve(context.Background(), "other", "two"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("live rate-limit state evicted: %v", err)
	}
	transport.mu.Lock()
	first.reset = time.Now().Add(-time.Second)
	transport.mu.Unlock()
	second, err := transport.reserve(context.Background(), "other", "two")
	if err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	if len(transport.buckets) != 1 || transport.buckets["one"] != nil {
		t.Error("expired idle metadata not reclaimed")
	}
	transport.mu.Unlock()
	transport.release("other", second, false)
}

func Test429PublishesGlobalFutureWaitWithoutResending(t *testing.T) {
	var sends atomic.Int32
	transport := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) {
		sends.Add(1)
		return &http.Response{StatusCode: 429, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"retry_after":3600,"global":true}`))}, nil
	})
	result, err := transport.Do(context.Background(), testRequest())
	if err != nil || result.StatusCode != 429 || sends.Load() != 1 {
		t.Fatalf("429 result=%+v sends=%d err=%v", result, sends.Load(), err)
	}
	transport.mu.Lock()
	until := transport.globalUntil
	transport.mu.Unlock()
	if time.Until(until) < time.Minute {
		t.Fatal("global 429 was not retained")
	}
	request := testRequest()
	request.Bucket = "independent"
	ctx, cancel := context.WithCancel(context.Background())
	// reserve directly provides a deterministic barrier before canceled admit.
	state, err := transport.reserve(ctx, request.Owner, request.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = transport.admit(ctx, state); !errors.Is(err, context.Canceled) {
		t.Fatalf("rate wait cancel=%v", err)
	}
	transport.release(request.Owner, state, false)
	if sends.Load() != 1 {
		t.Fatal("429 resent or global admission dispatched")
	}
}

func TestRemainingResetAndHeaderGlobalParsing(t *testing.T) {
	transport := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) { return successResponse(), nil })
	state, err := transport.reserve(context.Background(), "owner", "bucket")
	if err != nil {
		t.Fatal(err)
	}
	transport.update(state, 200, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset-After": {"3600"}}, nil)
	transport.mu.Lock()
	blocked := state.known && state.remaining == 0 && time.Until(state.reset) > time.Minute
	transport.mu.Unlock()
	if !blocked {
		t.Fatal("remaining/reset admission state lost")
	}
	transport.update(state, 429, http.Header{"X-Ratelimit-Global": {"true"}, "Retry-After": {"7200"}}, nil)
	transport.mu.Lock()
	global := time.Until(transport.globalUntil) > time.Hour
	transport.mu.Unlock()
	if !global {
		t.Fatal("header-only global 429 lost")
	}
	transport.release("owner", state, false)
	for _, invalid := range []string{"NaN", "+Inf", "-1", "1e100", "private"} {
		if _, ok := secondsDuration(invalid); ok {
			t.Fatalf("unsafe delay %q accepted", invalid)
		}
	}
}

func TestCloseCancelsAndJoinsAdmissionAndDispatch(t *testing.T) {
	entered := make(chan struct{})
	transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan error, 1)
	go func() { _, err := transport.Do(context.Background(), testRequest()); done <- err }()
	<-entered
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrClosed) {
		t.Fatalf("close error=%v", err)
	}
	if result, err := transport.Do(context.Background(), testRequest()); !errors.Is(err, ErrClosed) || result.Dispatched {
		t.Fatalf("post-close dispatched=%v err=%v", result.Dispatched, err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.active != 0 || len(transport.owners) != 0 {
		t.Fatal("Close returned with retained request slots")
	}
}
