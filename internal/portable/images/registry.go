package images

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/thirdscam/chatanium/internal/provision"
)

var repositoryPath = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
var dnsName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var tokenServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func approvedHTTPS(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 4096 || u.Scheme != "https" || u.User != nil || u.Host != u.Hostname() || u.Fragment != "" || !dnsName.MatchString(u.Host) || len(u.Host) > 253 || u.Opaque != "" {
		return nil, errors.New("registry authority must be an exact HTTPS DNS endpoint on port 443")
	}
	return u, nil
}

func parseRepository(s Source) (*url.URL, error) {
	u, err := approvedHTTPS(s.Reference)
	if err != nil {
		return nil, err
	}
	if u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || !repositoryPath.MatchString(strings.TrimPrefix(u.Path, "/")) || len(u.Path) > 256 {
		return nil, errors.New("registry approval requires an exact repository without tag or digest suffix")
	}
	if s.TokenURL != "" {
		t, err := approvedHTTPS(s.TokenURL)
		if err != nil {
			return nil, err
		}
		if t.Path == "" || t.RawPath != "" || t.RawQuery != "" || t.ForceQuery {
			return nil, errors.New("token authority requires an exact HTTPS endpoint without a query")
		}
	}
	if s.TokenService != "" && (s.TokenURL == "" || !tokenServiceName.MatchString(s.TokenService)) {
		return nil, errors.New("invalid approved registry token service")
	}
	if len(s.RedirectHosts) > 8 {
		return nil, errors.New("too many approved registry redirect authorities")
	}
	last := ""
	for _, h := range s.RedirectHosts {
		if h <= last || h == u.Host || len(h) > 253 || !dnsName.MatchString(h) {
			return nil, errors.New("redirect authorities must be exact sorted distinct external DNS names")
		}
		last = h
	}
	return u, nil
}

// No proxy or reusable host registry credentials. Each connection dials an
// already-validated literal, while TLS verifies the approved DNS authority.
func registryClient() (*http.Client, error) {
	local, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	localIPs := make(map[netip.Addr]bool, len(local))
	for _, addr := range local {
		if p, err := netip.ParsePrefix(addr.String()); err == nil {
			localIPs[p.Addr().Unmap()] = true
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  15 * time.Second,
		MaxResponseHeaderBytes: 32 << 10,
		DisableCompression:     true,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" || !dnsName.MatchString(host) {
				return nil, errors.New("unapproved registry socket authority")
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				ip = ip.Unmap()
				if localIPs[ip] || !publicRegistryAddress(ip) {
					continue
				}
				conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, errors.New("approved registry has no reachable public address")
		},
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

var registryDenied = func() []netip.Prefix {
	cidrs := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	out := make([]netip.Prefix, len(cidrs))
	for i, p := range cidrs {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}()
var ipv6Public = netip.MustParsePrefix("2000::/3")

func publicRegistryAddress(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" || ip.Is6() && !ipv6Public.Contains(ip) {
		return false
	}
	for _, p := range registryDenied {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

type registrySource struct {
	source  Source
	repo    *url.URL
	client  *http.Client
	staging *os.File
	token   string
}

func (s *registrySource) obtainToken(ctx context.Context) error {
	u, err := approvedHTTPS(s.source.TokenURL)
	if err != nil {
		return err
	}
	service := s.source.TokenService
	if service == "" {
		service = s.repo.Host
	}
	u.RawQuery = url.Values{"service": {service}, "scope": {"repository:" + strings.TrimPrefix(s.repo.Path, "/") + ":pull"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("approved registry token endpoint is unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("approved registry token endpoint rejected the request")
	}
	const max = 32 << 10
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil || len(b) > max {
		return errors.New("registry token response exceeds bound")
	}
	var v struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err = json.Unmarshal(b, &v); err != nil {
		return errors.New("invalid registry token response")
	}
	if v.Token == "" {
		v.Token = v.AccessToken
	}
	if v.Token == "" || len(v.Token) > 16<<10 || strings.IndexFunc(v.Token, func(c rune) bool { return c <= ' ' || c >= 0x7f }) >= 0 {
		return errors.New("invalid registry token value")
	}
	s.token = v.Token
	return nil
}

func (s *registrySource) fetch(ctx context.Context, kind byte, digest string, expected, max int64, reply io.Writer) (int64, error) {
	if !provision.ValidDigest(digest) || max <= 0 || expected > max {
		return 0, errors.New("invalid or over-budget registry request")
	}
	component, accept := "blobs", "application/octet-stream"
	if kind == provision.PortableFetchManifest {
		component = "manifests"
		accept = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"
	}
	u := s.repo.ResolveReference(&url.URL{Path: "/v2" + s.repo.Path + "/" + component + "/" + digest})
	tokenTried := s.token != ""
	for redirects := 0; redirects <= 3; {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Accept", accept)
		if u.Host == s.repo.Host && s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return 0, errors.New("approved registry object request failed")
		}
		if resp.StatusCode == http.StatusUnauthorized && u.Host == s.repo.Host && !tokenTried && s.source.TokenURL != "" {
			resp.Body.Close()
			tokenTried = true
			if err = s.obtainToken(ctx); err != nil {
				return 0, err
			}
			continue
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && kind == provision.PortableFetchBlob {
			next, err := resp.Location()
			resp.Body.Close()
			if err != nil {
				return 0, errors.New("invalid registry redirect")
			}
			v, err := approvedHTTPS(next.String())
			if err != nil {
				return 0, err
			}
			allowed := false
			for _, h := range s.source.RedirectHosts {
				if v.Host == h {
					allowed = true
					break
				}
			}
			if !allowed {
				return 0, errors.New("registry redirect authority was not approved")
			}
			u = v
			redirects++
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("approved registry object request returned HTTP %d", resp.StatusCode)
		}
		if resp.ContentLength > max || expected > 0 && resp.ContentLength >= 0 && resp.ContentLength != expected || resp.Header.Get("Content-Encoding") != "" {
			return 0, errors.New("invalid registry object length or encoding")
		}
		if err = s.staging.Truncate(0); err != nil {
			return 0, err
		}
		if _, err = s.staging.Seek(0, io.SeekStart); err != nil {
			return 0, err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(s.staging, h), io.LimitReader(resp.Body, max+1))
		if err != nil {
			return 0, err
		}
		if n <= 0 || n > max || expected != 0 && n != expected || "sha256:"+hex.EncodeToString(h.Sum(nil)) != digest {
			return 0, errors.New("registry source object hash or size mismatch")
		}
		if _, err = s.staging.Seek(0, io.SeekStart); err != nil {
			return 0, err
		}
		if err = provision.WritePortableSize(reply, n); err != nil {
			return 0, err
		}
		if _, err = io.CopyN(reply, s.staging, n); err != nil {
			return 0, err
		}
		return n, nil
	}
	return 0, errors.New("registry redirect limit exceeded")
}
