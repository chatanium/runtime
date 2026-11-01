package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/moby/moby/client"
)

type createReceiptKey struct{}

type createReceipt struct {
	kind     CreateKind
	identity string
	path     string
	status   int
	complete bool
	invalid  bool
	body     bytes.Buffer
}

func createRequest(ctx context.Context, kind CreateKind, identity string) (context.Context, *createReceipt) {
	receipt := &createReceipt{kind: kind, identity: identity}
	return context.WithValue(ctx, createReceiptKey{}, receipt), receipt
}

// SDK response hooks receive detached metadata and cannot wrap the real body.
// Capture at the transport boundary so only bytes actually read by the SDK
// contribute to the receipt's completion fence.
type createReceiptTransport struct{ base http.RoundTripper }

func (transport *createReceiptTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return response, err
	}
	if response != nil && response.Request == nil {
		response.Request = request
	}
	captureCreateResponse(response)
	return response, nil
}

func newCreateClient(endpoint string) (*client.Client, *http.Transport, error) {
	socket := strings.TrimPrefix(endpoint, "unix://")
	dialer := &net.Dialer{}
	transport := &http.Transport{DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	cli, err := client.New(client.WithHost(endpoint), client.WithHTTPClient(&http.Client{Transport: &createReceiptTransport{base: transport}, CheckRedirect: client.CheckRedirect}))
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return cli, transport, nil
}

// The pinned local Docker API invokes create synchronously. Its standard JSON
// error response is emitted only after the handler (including deferred rollback)
// returns. A complete negative receipt fences delayed publication, not leftover
// objects: normal ownership-checked inspection/removal is still mandatory.
// See moby 285b471 daemon/server/server.go and daemon/create.go.
func captureCreateResponse(response *http.Response) {
	if response == nil || response.Request == nil || response.Body == nil {
		return
	}
	receipt, ok := response.Request.Context().Value(createReceiptKey{}).(*createReceipt)
	if !ok || response.Request.Method != http.MethodPost {
		return
	}
	path := response.Request.URL.Path
	if strings.HasPrefix(path, "/v") {
		version, suffix, found := strings.Cut(strings.TrimPrefix(path, "/v"), "/")
		if !found || version == "" || strings.Trim(version, "0123456789.") != "" {
			return
		}
		path = "/" + suffix
	}
	if (receipt.kind == CreateContainer && (path != "/containers/create" || response.Request.URL.Query().Get("name") != receipt.identity)) || (receipt.kind == CreateNetwork && path != "/networks/create") {
		return
	}
	// These are documented synchronous create errors. Gateway/time-out and
	// unknown statuses are deliberately not negative-result evidence.
	switch response.StatusCode {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError:
	default:
		return
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return
	}
	receipt.path = response.Request.URL.RequestURI()
	receipt.status = response.StatusCode
	response.Body = &createReceiptBody{ReadCloser: response.Body, receipt: receipt}
}

type createReceiptBody struct {
	io.ReadCloser
	receipt *createReceipt
}

func (body *createReceiptBody) Read(buffer []byte) (int, error) {
	n, err := body.ReadCloser.Read(buffer)
	// Match the SDK's finite error-body bound. A truncated, oversized, or
	// interrupted response remains indeterminate even if its status looked final.
	if body.receipt.body.Len()+n > 1<<20 {
		body.receipt.invalid = true
	} else if !body.receipt.invalid {
		body.receipt.body.Write(buffer[:n])
	}
	if err == io.EOF {
		body.receipt.complete = true
	} else if err != nil {
		body.receipt.invalid = true
	}
	return n, err
}

func (receipt *createReceipt) rejection() string {
	if !receipt.complete || receipt.invalid || receipt.status == 0 {
		return ""
	}
	var response struct {
		Message string `json:"message"`
	}
	decoder := json.NewDecoder(bytes.NewReader(receipt.body.Bytes()))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&response) != nil || strings.TrimSpace(response.Message) == "" {
		return ""
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ""
	}
	// Retain the finite receipt, never the daemon's potentially sensitive text.
	proof, _ := json.Marshal(struct {
		Source string `json:"source"`
		Method string `json:"method"`
		URI    string `json:"uri"`
		Status int    `json:"status"`
	}{"local-docker-http", http.MethodPost, receipt.path, receipt.status})
	return string(proof)
}

func recordCreateRejection(cause error, receipt *createReceipt, journal CreateJournal, owner Ownership, timeout time.Duration) error {
	if cause == nil {
		return nil
	}
	proof := receipt.rejection()
	if proof == "" {
		return cause
	}
	// A complete response may race the API deadline. Use a separate finite
	// journal operation; a failed commit retains SUBMITTED and all claims.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return errors.Join(cause, journal.RejectCreate(ctx, owner, receipt.kind, receipt.identity, proof))
}
