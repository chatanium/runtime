package host

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/moby/moby/client"
)

const ImageManifestLabel = "org.chatanium.flexmodule.manifest.v2"

type imageResponseBoundKey struct{}

// ImageInspect buffers its response before unmarshalling. Bound the underlying
// HTTP body, not just the decoded label, so unrelated malicious image metadata
// cannot allocate an unbounded intermediate response in the official SDK.
type boundedImageTransport struct{ base *http.Transport }

func (t *boundedImageTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	limit, ok := request.Context().Value(imageResponseBoundKey{}).(int64)
	if !ok || limit <= 0 {
		return nil, invalid("image inspect response bound required")
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > limit {
		response.Body.Close()
		return nil, errors.New("Docker image inspect response exceeds control bound")
	}
	response.Body = &boundedImageBody{body: response.Body, remaining: limit}
	return response, nil
}

type boundedImageBody struct {
	body      io.ReadCloser
	remaining int64
	exceeded  bool
}

func (b *boundedImageBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.exceeded {
		return 0, errors.New("Docker image inspect response exceeds control bound")
	}
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.body.Read(extra[:])
		if n > 0 {
			b.exceeded = true
			return 0, errors.New("Docker image inspect response exceeds control bound")
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:int(b.remaining)]
	}
	n, err := b.body.Read(p)
	b.remaining -= int64(n)
	return n, err
}
func (b *boundedImageBody) Close() error { return b.body.Close() }

func newBoundedImageClient(endpoint string) (*client.Client, *http.Transport, error) {
	socket := strings.TrimPrefix(endpoint, "unix://")
	dialer := &net.Dialer{}
	transport := &http.Transport{DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	cli, err := client.New(client.WithHost(endpoint), client.WithHTTPClient(&http.Client{Transport: &boundedImageTransport{base: transport}, CheckRedirect: client.CheckRedirect}))
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	return cli, transport, nil
}
func validateImageDigest(digest string) error {
	repository, sum, ok := strings.Cut(digest, "@sha256:")
	if !ok || repository == "" || !strings.Contains(repository, "/") || strings.ContainsAny(repository, "\x00\r\n ?#") || len(sum) != 64 {
		return invalid("immutable registry/repository image digest required")
	}
	if _, err := hex.DecodeString(sum); err != nil || sum != strings.ToLower(sum) {
		return invalid("invalid image SHA256 digest")
	}
	return nil
}
func (p *DockerPlatform) inspectPinnedImage(ctx context.Context, digest string, maxBytes int64) (client.ImageInspectResult, error) {
	if err := validateImageDigest(digest); err != nil {
		return client.ImageInspectResult{}, err
	}
	if maxBytes <= 0 {
		return client.ImageInspectResult{}, invalid("finite image declaration bound required")
	}
	api, cancel := context.WithTimeout(ctx, p.cfg.APIDeadline)
	defer cancel()
	image, err := p.images.ImageInspect(context.WithValue(api, imageResponseBoundKey{}, maxBytes), digest)
	if err != nil {
		return client.ImageInspectResult{}, err
	}
	if !slices.Contains(image.RepoDigests, digest) || image.Config == nil {
		return client.ImageInspectResult{}, prerequisite(errors.New("prepared image digest mismatch"))
	}
	declaration := image.Config.Labels[ImageManifestLabel]
	if declaration == "" || int64(len(declaration)) > maxBytes || !json.Valid([]byte(declaration)) {
		return client.ImageInspectResult{}, invalid("missing, invalid, or oversized immutable image manifest declaration")
	}
	return image, nil
}
func (p *DockerPlatform) ImageManifest(ctx context.Context, digest string, maxBytes int64) ([]byte, error) {
	image, err := p.inspectPinnedImage(ctx, digest, maxBytes)
	if err != nil {
		return nil, err
	}
	return []byte(image.Config.Labels[ImageManifestLabel]), nil
}
