// Package http implements the host-only, single-attempt Discord HTTP boundary.
package http

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	ErrInvalidConfig    = errors.New("DISCORD_HTTP_INVALID_CONFIG")
	ErrInvalidRequest   = errors.New("DISCORD_HTTP_INVALID_REQUEST")
	ErrBodyTooLarge     = errors.New("DISCORD_HTTP_BODY_TOO_LARGE")
	ErrHeadersTooLarge  = errors.New("DISCORD_HTTP_HEADERS_TOO_LARGE")
	ErrResponseTooLarge = errors.New("DISCORD_HTTP_RESPONSE_TOO_LARGE")
	ErrCapacity         = errors.New("DISCORD_HTTP_CAPACITY_EXHAUSTED")
	ErrClosed           = errors.New("DISCORD_HTTP_CLOSED")
	ErrTransport        = errors.New("DISCORD_HTTP_TRANSPORT_FAILURE")
	ErrFile             = errors.New("DISCORD_HTTP_FILE_FAILURE")
)

type Config struct {
	RequestDeadline     time.Duration
	JSONMaxBytes        int64
	ResponseMaxBytes    int64
	HeaderMaxBytes      int64
	RequestsPerInstance int
	RequestsPerHost     int
	RateLimitBuckets    int
	RateLimitRetention  time.Duration
}

type Request struct {
	Owner         string
	Method        string
	Path          string
	Query         url.Values
	Bucket        string
	Authorization string
	AuditReason   *string
	Locale        *string
	JSON          []byte
	Files         []File
	MaxBodyBytes  int64
}

// Open must honor ctx; Close on its result must interrupt an ongoing Read.
// The caller retains its source lease until Do has returned.
type File struct {
	Name        string
	Filename    string
	ContentType string
	Size        int64
	Open        func(context.Context) (io.ReadCloser, error)
}

type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Dispatched bool
}

type Transport struct {
	config      Config
	client      http.Client
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
	changed     chan struct{}
	active      int
	owners      map[string]int
	buckets     map[string]*bucket
	globalUntil time.Time
	calls       sync.WaitGroup
	closeOnce   sync.Once
}

// New copies the trusted client; redirects and transparent replay are disabled.
// A standard Transport is cloned so its response-header and connection bounds
// do not mutate the caller's transport. A custom RoundTripper must itself honor
// request cancellation and enforce bounded header parsing before returning.
func New(config Config, client *http.Client) (*Transport, error) {
	if config.RequestDeadline <= 0 || config.JSONMaxBytes <= 0 || config.ResponseMaxBytes <= 0 || config.HeaderMaxBytes <= 0 || config.RequestsPerInstance <= 0 || config.RequestsPerHost <= 0 || config.RateLimitBuckets <= 0 || config.RateLimitRetention <= 0 || config.ResponseMaxBytes == math.MaxInt64 {
		return nil, ErrInvalidConfig
	}
	var owned http.Client
	if client != nil {
		owned = *client
	}
	owned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Cookies are not part of the fixed credential contract.
	owned.Jar = nil
	base := owned.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if standard, ok := base.(*http.Transport); ok {
		clone := standard.Clone()
		clone.MaxResponseHeaderBytes = config.HeaderMaxBytes
		clone.MaxConnsPerHost = config.RequestsPerHost
		clone.MaxIdleConnsPerHost = config.RequestsPerHost
		clone.DisableCompression = true
		// Fresh HTTP/1 connections avoid net/http's implicit replay on stale
		// pooled connections and HTTP/2 REFUSED_STREAM retry paths.
		clone.DisableKeepAlives = true
		clone.Protocols = new(http.Protocols)
		clone.Protocols.SetHTTP1(true)
		// Clone initializes the source transport's HTTP/2 defaults and can
		// retain its h2 ALPN advertisement. Protocols alone does not trim
		// NextProtos when HTTP/2 initialization is disabled on this clone.
		if clone.TLSClientConfig != nil {
			clone.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		owned.Transport = clone
	} else {
		owned.Transport = base
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Transport{config: config, client: owned, ctx: ctx, cancel: cancel, changed: make(chan struct{}), owners: make(map[string]int), buckets: make(map[string]*bucket)}, nil
}

func (t *Transport) signalLocked() { close(t.changed); t.changed = make(chan struct{}) }

func (t *Transport) failure(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		if t.ctx.Err() != nil {
			return ErrClosed
		}
		return err
	}
	return fallback
}

// Close cancels and joins all calls, including admission waits and producers.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.cancel()
		t.signalLocked()
		t.mu.Unlock()
		t.calls.Wait()
		t.client.CloseIdleConnections()
	})
	return nil
}

// Do makes exactly one attempt. Non-2xx responses are returned without a Go
// error for host-side typed projection; no remote body or URL appears in errors.
func (t *Transport) Do(ctx context.Context, request Request) (result Response, err error) {
	if ctx == nil {
		return result, ErrInvalidRequest
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return result, ErrClosed
	}
	t.calls.Add(1)
	t.mu.Unlock()
	defer t.calls.Done()
	work, cancel := context.WithTimeout(ctx, t.config.RequestDeadline)
	stop := context.AfterFunc(t.ctx, cancel)
	defer func() { stop(); cancel() }()
	if work.Err() != nil {
		return result, t.failure(work, ErrTransport)
	}
	if err = t.validate(request); err != nil {
		return result, err
	}
	state, err := t.reserve(work, request.Owner, request.Bucket)
	if err != nil {
		return result, err
	}
	admitted := false
	defer func() { t.release(request.Owner, state, admitted) }()
	prepared, err := t.prepare(request)
	if err != nil {
		return result, err
	}
	if err = t.admit(work, state); err != nil {
		return result, err
	}
	admitted = true

	body, producer := prepared.open(work, cancel)
	if producer != nil {
		defer func() {
			producer.abort()
			producerErr := producer.join()
			if producerErr != nil && (err == nil || errors.Is(producerErr, ErrFile)) && ctx.Err() == nil && t.ctx.Err() == nil && work.Err() != context.DeadlineExceeded {
				err = ErrFile
			}
		}()
	}
	httpRequest, requestErr := http.NewRequestWithContext(work, request.Method, prepared.target, body)
	if requestErr != nil {
		return result, ErrInvalidRequest
	}
	httpRequest.Header = prepared.header
	httpRequest.ContentLength = prepared.length
	// GetBody is deliberately nil even for replayable JSON: net/http must not
	// retry a request on a reused connection after an ambiguous network failure.
	httpRequest.GetBody = nil
	if work.Err() != nil {
		return result, t.failure(work, ErrTransport)
	}
	result.Dispatched = true
	response, sendErr := t.client.Do(httpRequest)
	if response != nil && response.Body != nil {
		responseBody := &ownedReader{ReadCloser: response.Body}
		response.Body = responseBody
		stopRead := context.AfterFunc(work, func() { _ = responseBody.Close() })
		defer func() {
			stopRead()
			if closeErr := responseBody.Close(); closeErr != nil && err == nil {
				err = t.failure(work, ErrTransport)
			}
		}()
	}
	if sendErr != nil {
		return result, t.failure(work, ErrTransport)
	}
	if response == nil || response.Body == nil {
		return result, ErrTransport
	}
	result.StatusCode = response.StatusCode
	if headerSize(response.Header, t.config.HeaderMaxBytes) < 0 {
		return result, ErrHeadersTooLarge
	}
	t.update(state, response.StatusCode, response.Header, nil)
	result.Header = response.Header.Clone()
	if response.ContentLength > t.config.ResponseMaxBytes {
		return result, ErrResponseTooLarge
	}
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, t.config.ResponseMaxBytes+1))
	if response.StatusCode == http.StatusTooManyRequests {
		t.update(state, response.StatusCode, response.Header, payload)
	}
	if readErr != nil {
		return result, t.failure(work, ErrTransport)
	}
	if int64(len(payload)) > t.config.ResponseMaxBytes {
		return result, ErrResponseTooLarge
	}
	if work.Err() != nil {
		return result, t.failure(work, ErrTransport)
	}
	result.Body = payload
	return result, nil
}
