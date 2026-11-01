package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testConfig() Config {
	return Config{RequestDeadline: time.Second * 5, JSONMaxBytes: 4096, ResponseMaxBytes: 4096, HeaderMaxBytes: 8192, RequestsPerInstance: 2, RequestsPerHost: 4, RateLimitBuckets: 8, RateLimitRetention: time.Minute}
}
func testRequest() Request {
	return Request{Owner: "owner", Method: http.MethodPost, Path: "/api/v10/channels/1/messages", Bucket: "messages:1", JSON: []byte(`{"content":"hello"}`), MaxBodyBytes: 1 << 20}
}
func newTestTransport(t *testing.T, config Config, roundTrip roundTripFunc) *Transport {
	t.Helper()
	transport, err := New(config, &http.Client{Transport: roundTrip})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}
func successResponse() *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}
}

func TestConfigRequiresExplicitFinitePositiveBounds(t *testing.T) {
	cases := []func(*Config){func(c *Config) { c.RequestDeadline = 0 }, func(c *Config) { c.JSONMaxBytes = 0 }, func(c *Config) { c.ResponseMaxBytes = 0 }, func(c *Config) { c.ResponseMaxBytes = math.MaxInt64 }, func(c *Config) { c.HeaderMaxBytes = 0 }, func(c *Config) { c.RequestsPerInstance = 0 }, func(c *Config) { c.RequestsPerHost = 0 }, func(c *Config) { c.RateLimitBuckets = 0 }, func(c *Config) { c.RateLimitRetention = 0 }}
	for _, change := range cases {
		config := testConfig()
		change(&config)
		if _, err := New(config, nil); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("invalid config: %v", err)
		}
	}
}

func TestMultipartExactLengthEscapingAndNoCountingReads(t *testing.T) {
	var opened int
	transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "discord.com" || r.GetBody != nil {
			t.Errorf("request escaped fixed single-attempt target")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if int64(len(body)) != r.ContentLength {
			t.Errorf("ContentLength=%d actual=%d", r.ContentLength, len(body))
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			return nil, err
		}
		reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		payload, err := reader.NextPart()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(payload)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(data, testRequest().JSON) {
			t.Errorf("payload changed: %q", data)
		}
		file, err := reader.NextPart()
		if err != nil {
			return nil, err
		}
		if file.FormName() != "files[0]" || file.FileName() != `a"b.txt` {
			t.Errorf("metadata changed: %q %q", file.FormName(), file.FileName())
		}
		data, err = io.ReadAll(file)
		if err != nil {
			return nil, err
		}
		if string(data) != "abc" {
			t.Errorf("file bytes changed")
		}
		if _, err = reader.NextPart(); err != io.EOF {
			t.Errorf("unexpected final part: %v", err)
		}
		return successResponse(), nil
	})
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: `a"b.txt`, ContentType: "text/plain", Size: 3, Open: func(context.Context) (io.ReadCloser, error) {
		opened++
		return io.NopCloser(strings.NewReader("abc")), nil
	}}}
	prepared, err := transport.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if opened != 0 {
		t.Fatal("counting opened file")
	}
	request.MaxBodyBytes = prepared.length - 1
	if result, err := transport.Do(context.Background(), request); !errors.Is(err, ErrBodyTooLarge) || result.Dispatched || opened != 0 {
		t.Fatalf("over limit result=%+v err=%v opens=%d", result, err, opened)
	}
	request.MaxBodyBytes = prepared.length
	result, err := transport.Do(context.Background(), request)
	if err != nil || !result.Dispatched || opened != 1 {
		t.Fatalf("exact bound result=%+v err=%v opens=%d", result, err, opened)
	}
}

func TestTargetMetadataAndSizeRejectionBeforeDispatch(t *testing.T) {
	var sends atomic.Int32
	transport := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) { sends.Add(1); return successResponse(), nil })
	for _, path := range []string{"https://evil.invalid/api/v10/x", "//evil.invalid/x", "/api/v10/../x", "/api/v10/%2e%2e/x", "/api/v10/x?token=secret", "/api/v10/x#fragment", "/api/v10/x\\y", "/api/v10/%00"} {
		r := testRequest()
		r.Path = path
		if result, err := transport.Do(context.Background(), r); !errors.Is(err, ErrInvalidRequest) || result.Dispatched {
			t.Fatalf("path %q dispatched=%v err=%v", path, result.Dispatched, err)
		}
	}
	for _, name := range []string{"bad\r\nX-Secret: value", "bad\x00name", ""} {
		r := testRequest()
		r.Files = []File{{Name: "files[0]", Filename: name, ContentType: "text/plain", Size: 1, Open: func(context.Context) (io.ReadCloser, error) {
			t.Error("invalid metadata opened file")
			return nil, ErrFile
		}}}
		if _, err := transport.Do(context.Background(), r); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("metadata err=%v", err)
		}
	}
	r := testRequest()
	r.JSON = make([]byte, testConfig().JSONMaxBytes+1)
	if _, err := transport.Do(context.Background(), r); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("JSON bound err=%v", err)
	}
	r = testRequest()
	r.Files = []File{{Name: "files[0]", Filename: "huge", ContentType: "text/plain", Size: math.MaxInt64, Open: func(context.Context) (io.ReadCloser, error) { t.Error("overflow opened file"); return nil, ErrFile }}}
	r.MaxBodyBytes = math.MaxInt64
	if _, err := transport.Do(context.Background(), r); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("overflow err=%v", err)
	}
	if sends.Load() != 0 {
		t.Fatalf("invalid requests dispatched: %d", sends.Load())
	}
}

func TestResponseBoundSafeErrorsAndRedirectNoReplay(t *testing.T) {
	var sends int
	transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) {
		sends++
		if sends == 1 {
			return &http.Response{StatusCode: 307, Header: http.Header{"Location": {"https://secret.invalid/token"}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
		}
		return nil, errors.New("https://secret.invalid/token Authorization: private")
	})
	result, err := transport.Do(context.Background(), testRequest())
	if err != nil || result.StatusCode != 307 || sends != 1 {
		t.Fatalf("redirect replay result=%+v sends=%d err=%v", result, sends, err)
	}
	_, err = transport.Do(context.Background(), testRequest())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), "secret") || sends != 2 {
		t.Fatalf("unsafe/retried failure sends=%d err=%v", sends, err)
	}
	for _, knownLength := range []bool{false, true} {
		var closed atomic.Int32
		bounded := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) {
			response := successResponse()
			response.Body = &countCloseReader{Reader: strings.NewReader(strings.Repeat("x", 4097)), closed: &closed}
			if knownLength {
				response.ContentLength = 4097
			}
			return response, nil
		})
		result, err := bounded.Do(context.Background(), testRequest())
		if !errors.Is(err, ErrResponseTooLarge) || len(result.Body) != 0 || closed.Load() != 1 {
			t.Fatalf("response bound known=%v close=%d err=%v", knownLength, closed.Load(), err)
		}
	}
}

type countCloseReader struct {
	io.Reader
	closed *atomic.Int32
}

func (r *countCloseReader) Close() error { r.closed.Add(1); return nil }

type blockingFile struct {
	entered  chan struct{}
	closed   chan struct{}
	once     sync.Once
	readOnce sync.Once
}

func (r *blockingFile) Read([]byte) (int, error) {
	r.readOnce.Do(func() { close(r.entered) })
	<-r.closed
	return 0, io.ErrClosedPipe
}
func (r *blockingFile) Close() error { r.once.Do(func() { close(r.closed) }); return nil }

func TestCancelClosesReaderAndJoinsProducer(t *testing.T) {
	file := &blockingFile{entered: make(chan struct{}), closed: make(chan struct{})}
	transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) { _, err := io.Copy(io.Discard, r.Body); return nil, err })
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "blocked", ContentType: "application/octet-stream", Size: 10, Open: func(context.Context) (io.ReadCloser, error) { return file, nil }}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := transport.Do(ctx, request); done <- err }()
	<-file.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error: %v", err)
	}
	select {
	case <-file.closed:
	default:
		t.Fatal("Do returned with live reader")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.active != 0 || len(transport.owners) != 0 || transport.buckets[request.Bucket].refs != 0 || transport.buckets[request.Bucket].busy {
		t.Fatal("cancellation retained admission state")
	}
}

func TestFileSizeMismatchAndLateCloseFailurePropagate(t *testing.T) {
	for _, source := range []string{"ab", "abcd"} {
		transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) {
			_, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				return nil, err
			}
			return successResponse(), nil
		})
		r := testRequest()
		r.Files = []File{{Name: "files[0]", Filename: "size", ContentType: "text/plain", Size: 3, Open: func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(source)), nil }}}
		if _, err := transport.Do(context.Background(), r); !errors.Is(err, ErrFile) {
			t.Fatalf("source=%q err=%v", source, err)
		}
	}
	transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) {
		_, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			return nil, err
		}
		return successResponse(), nil
	})
	r := testRequest()
	r.Files = []File{{Name: "files[0]", Filename: "close", ContentType: "text/plain", Size: 3, Open: func(context.Context) (io.ReadCloser, error) { return closeFailure{strings.NewReader("abc")}, nil }}}
	if _, err := transport.Do(context.Background(), r); !errors.Is(err, ErrFile) {
		t.Fatalf("late close err=%v", err)
	}
}

type closeFailure struct{ io.Reader }

func (closeFailure) Close() error { return errors.New("private filesystem failure") }

func TestCancelClosesBlockedResponseBody(t *testing.T) {
	body := &blockingFile{entered: make(chan struct{}), closed: make(chan struct{})}
	transport := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) {
		response := successResponse()
		response.Body = body
		return response, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := transport.Do(ctx, testRequest()); done <- err }()
	<-body.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("response cancel error=%v", err)
	}
	select {
	case <-body.closed:
	default:
		t.Fatal("response body remained open")
	}
}

func TestEmptyFileReopensForEveryExplicitCall(t *testing.T) {
	var opens atomic.Int32
	transport := newTestTransport(t, testConfig(), func(r *http.Request) (*http.Response, error) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return nil, err
		}
		return successResponse(), nil
	})
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "empty", ContentType: "application/octet-stream", Size: 0, Open: func(context.Context) (io.ReadCloser, error) {
		opens.Add(1)
		return io.NopCloser(strings.NewReader("")), nil
	}}}
	for range 2 {
		if _, err := transport.Do(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if opens.Load() != 2 {
		t.Fatalf("fresh explicit calls opened %d readers", opens.Load())
	}
}

func TestResponseHeadersAreBoundedIncludingEmptyValueLists(t *testing.T) {
	config := testConfig()
	transport := newTestTransport(t, config, func(*http.Request) (*http.Response, error) {
		response := successResponse()
		response.Header[strings.Repeat("x", int(config.HeaderMaxBytes)+1)] = nil
		return response, nil
	})
	if result, err := transport.Do(context.Background(), testRequest()); !errors.Is(err, ErrHeadersTooLarge) || len(result.Body) != 0 || len(result.Header) != 0 {
		t.Fatalf("header bound result=%+v err=%v", result, err)
	}
}

func TestHTTPFailureWhileSourceBlockedPreservesTransportError(t *testing.T) {
	file := &blockingFile{entered: make(chan struct{}), closed: make(chan struct{})}
	readDone := make(chan struct{})
	transport := newTestTransport(t, testConfig(), func(request *http.Request) (*http.Response, error) {
		go func() {
			_, _ = io.Copy(io.Discard, request.Body)
			close(readDone)
		}()
		<-file.entered
		return nil, errors.New("private network failure")
	})
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "blocked", ContentType: "application/octet-stream", Size: 10, Open: func(context.Context) (io.ReadCloser, error) {
		return file, nil
	}}}
	result, err := transport.Do(context.Background(), request)
	<-readDone
	if err != ErrTransport || !result.Dispatched {
		t.Fatalf("network failure masked by reader cancellation: result=%+v err=%v", result, err)
	}
	select {
	case <-file.closed:
	default:
		t.Fatal("transport error returned before closing its source")
	}
}
