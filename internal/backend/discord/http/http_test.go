package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Dial only the local TLS test server while preserving the production origin,
// URL, Host, TLS request flow and real standard-Transport body framing.
func localHTTPTransport(t *testing.T, handler http.Handler) (*Transport, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	trusted := client.Transport.(*http.Transport).Clone()
	trusted.TLSClientConfig = trusted.TLSClientConfig.Clone()
	certificate := server.Certificate()
	if len(certificate.DNSNames) > 0 {
		trusted.TLSClientConfig.ServerName = certificate.DNSNames[0]
	} else if len(certificate.IPAddresses) > 0 {
		trusted.TLSClientConfig.ServerName = certificate.IPAddresses[0].String()
	} else {
		t.Fatal("local TLS certificate has no verifiable hostname")
	}
	trusted.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	client.Transport = trusted
	transport, err := New(testConfig(), client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport, server
}

func TestActualHTTPSCloneNegotiatesOnlyHTTP1FromHTTP2Default(t *testing.T) {
	var mutations atomic.Int32
	request := testRequest()
	request.Path = "/api/v10/applications/1/guilds/2/commands"
	request.JSON = []byte(`{"name":"transport-test","description":"transport test"}`)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			mutations.Add(1)
			if r.Host != "discord.com" || r.URL.Path != request.Path || r.ProtoMajor != 1 || r.TLS.NegotiatedProtocol != "http/1.1" {
				t.Error("bounded command request did not use the fixed HTTP/1 origin and protocol")
			}
			if !r.Close || r.ContentLength != int64(len(request.JSON)) || len(r.TransferEncoding) != 0 {
				t.Error("bounded command request lost its single-attempt body framing")
			}
			body, err := io.ReadAll(r.Body)
			if err != nil || !bytes.Equal(body, request.JSON) {
				t.Error("bounded command request body changed")
			}
		}
		_, _ = io.WriteString(w, `{"id":"1"}`)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.StartTLS()
	t.Cleanup(server.Close)

	// Use the real default clone path: it initializes and inherits h2 ALPN.
	// Change only local routing and certificate trust, not protocol selection.
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	certificate := server.Certificate()
	if len(certificate.DNSNames) > 0 {
		base.TLSClientConfig.ServerName = certificate.DNSNames[0]
	} else if len(certificate.IPAddresses) > 0 {
		base.TLSClientConfig.ServerName = certificate.IPAddresses[0].String()
	} else {
		t.Fatal("local TLS certificate has no verifiable hostname")
	}
	base.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	t.Cleanup(base.CloseIdleConnections)
	client := &http.Client{Transport: base, Timeout: testConfig().RequestDeadline}

	// The same trusted base must actually negotiate HTTP/2 before cloning it
	// into the single-attempt boundary; an HTTP/1-only test server misses this.
	control, err := client.Get("https://discord.com/api/v10/gateway")
	if err != nil {
		t.Fatal("local HTTP/2 positive control failed")
	}
	_, readErr := io.Copy(io.Discard, control.Body)
	closeErr := control.Body.Close()
	if readErr != nil || closeErr != nil || control.ProtoMajor != 2 || control.TLS.NegotiatedProtocol != "h2" {
		t.Fatal("local positive control did not complete over HTTP/2")
	}

	transport, err := New(testConfig(), client)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	result, err := transport.Do(context.Background(), request)
	if err != nil || result.StatusCode != http.StatusOK || mutations.Load() != 1 {
		t.Fatalf("bounded command status=%d mutations=%d error=%v", result.StatusCode, mutations.Load(), err)
	}
}

func TestActualHTTPSMultipartHasExactNonChunkedLength(t *testing.T) {
	const fileSize = 256 * 1024
	var received atomic.Int64
	transport, _ := localHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "discord.com" || r.URL.Path != testRequest().Path || r.ProtoMajor != 1 {
			t.Errorf("unexpected fixed origin/protocol: %s %s %s", r.Host, r.URL.Path, r.Proto)
		}
		if r.ContentLength <= fileSize || len(r.TransferEncoding) != 0 {
			t.Errorf("not exact ContentLength: %d %v", r.ContentLength, r.TransferEncoding)
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Error(err)
			http.Error(w, "invalid", 400)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		payload, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		if _, err = io.Copy(io.Discard, payload); err != nil {
			t.Error(err)
			return
		}
		file, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		count, err := io.Copy(io.Discard, file)
		if err != nil {
			t.Error(err)
			return
		}
		if count != fileSize {
			t.Errorf("file size: %d", count)
		}
		if _, err = reader.NextPart(); err != io.EOF {
			t.Errorf("unexpected trailer: %v", err)
		}
		received.Store(count)
		_, _ = io.WriteString(w, `{"id":"1"}`)
	}))
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "stream.bin", ContentType: "application/octet-stream", Size: fileSize, Open: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(io.LimitReader(repeatByteReader{}, fileSize)), nil
	}}}
	result, err := transport.Do(context.Background(), request)
	if err != nil || result.StatusCode != 200 || received.Load() != fileSize {
		t.Fatalf("HTTPS result=%+v received=%d err=%v", result, received.Load(), err)
	}
}

type repeatByteReader struct{}

func (repeatByteReader) Read(data []byte) (int, error) {
	for i := range data {
		data[i] = 'x'
	}
	return len(data), nil
}

func TestActualHTTPSRedirectDoesNotResendCredentials(t *testing.T) {
	var requests atomic.Int32
	transport, _ := localHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "https://discord.com/api/v10/redirected")
		w.WriteHeader(307)
	}))
	request := testRequest()
	request.Authorization = "Bot private-token"
	result, err := transport.Do(context.Background(), request)
	if err != nil || result.StatusCode != 307 || requests.Load() != 1 {
		t.Fatalf("redirect sends=%d status=%d err=%v", requests.Load(), result.StatusCode, err)
	}
}

func TestHTTPFailureBeforeBodyConsumptionCannotStrandProducer(t *testing.T) {
	transport := newTestTransport(t, testConfig(), func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })
	var opened atomic.Int32
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "stream.bin", ContentType: "application/octet-stream", Size: 1024, Open: func(context.Context) (io.ReadCloser, error) {
		opened.Add(1)
		return io.NopCloser(strings.NewReader(strings.Repeat("x", 1024))), nil
	}}}
	result, err := transport.Do(context.Background(), request)
	if err != ErrTransport || !result.Dispatched || opened.Load() != 0 {
		t.Fatalf("HTTP failure result=%+v opened=%d err=%v", result, opened.Load(), err)
	}
}

func TestActualTLSFailurePreservesTransportErrorWithMultipart(t *testing.T) {
	var requests atomic.Int32
	transport, _ := localHTTPTransport(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	transport.client.Transport.(*http.Transport).TLSClientConfig.ServerName = "mismatch.invalid"
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "stream.bin", ContentType: "application/octet-stream", Size: 1024, Open: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(io.LimitReader(repeatByteReader{}, 1024)), nil
	}}}
	result, err := transport.Do(context.Background(), request)
	if err != ErrTransport || !result.Dispatched || requests.Load() != 0 {
		t.Fatalf("TLS error masked by producer cleanup: result=%+v requests=%d err=%v", result, requests.Load(), err)
	}
}

func TestActualHTTPSUploadedPublicBoundaryRemainsOneCompleteFile(t *testing.T) {
	const oldPublicBoundary = "chatanium-flexmodule-discord-v2-7cb864eaf51d4c829b0e"
	// These bytes are fixed before request preparation and include a complete
	// attempt to inject another payload_json part using the old public framing.
	uploaded := []byte("prefix\r\n--" + oldPublicBoundary + "\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n{\"content\":\"forged\"}\r\n--" + oldPublicBoundary + "--\r\nsuffix")
	var received atomic.Int32
	transport, _ := localHTTPTransport(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TransferEncoding) != 0 {
			t.Errorf("multipart body was chunked: %v", r.TransferEncoding)
		}
		// This adversarial fixture is deliberately small; production transport
		// still streams immutable source bytes without buffering or scanning.
		wire, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		if int64(len(wire)) != r.ContentLength {
			t.Errorf("wire length=%d advertised=%d", len(wire), r.ContentLength)
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Error(err)
			return
		}
		if params["boundary"] == oldPublicBoundary || params["boundary"] == "" {
			t.Errorf("predictable or missing multipart boundary")
		}
		reader := multipart.NewReader(bytes.NewReader(wire), params["boundary"])
		payload, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		actualJSON, err := io.ReadAll(payload)
		if err != nil || payload.FormName() != "payload_json" || !bytes.Equal(actualJSON, testRequest().JSON) {
			t.Errorf("validated JSON part changed: name=%q payload=%q err=%v", payload.FormName(), actualJSON, err)
		}
		file, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		actualFile, err := io.ReadAll(file)
		if err != nil || file.FormName() != "files[0]" || !bytes.Equal(actualFile, uploaded) {
			t.Errorf("uploaded bytes escaped their file part: name=%q size=%d want=%d err=%v", file.FormName(), len(actualFile), len(uploaded), err)
		}
		if _, err := reader.NextPart(); err != io.EOF {
			t.Errorf("uploaded framing injected an extra part: %v", err)
		}
		received.Add(1)
		_, _ = io.WriteString(w, `{}`)
	}))
	request := testRequest()
	request.Files = []File{{Name: "files[0]", Filename: "adversarial.bin", ContentType: "application/octet-stream", Size: int64(len(uploaded)), Open: func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(uploaded)), nil
	}}}
	first, err := transport.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transport.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	if first.boundary == second.boundary {
		t.Fatal("separate requests reused their multipart boundary")
	}
	// Each boundary has a fixed encoded size, so a fresh prepared request
	// retains the same exact body-size bound despite unpredictable framing.
	request.MaxBodyBytes = first.length
	result, err := transport.Do(context.Background(), request)
	if err != nil || result.StatusCode != http.StatusOK || received.Load() != 1 {
		t.Fatalf("adversarial upload result=%+v received=%d err=%v", result, received.Load(), err)
	}
}
