package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// Expectations are operator annotations, not grants or fixture PASS verdicts.
// The host must correlate these observations with topology, packet counters,
// controlled responders, and independently reachable positive controls.
type networkConfig struct {
	ExpectedEgress     string            `json:"expected_egress"`
	OperationTimeoutMS int               `json:"operation_timeout_ms"`
	TCP                []tcpTarget       `json:"tcp_targets"`
	DNS                []dnsQuery        `json:"dns_queries"`
	HTTP               []httpTarget      `json:"http_requests"`
	Fresh              []freshResolution `json:"fresh_resolutions"`
}

type tcpTarget struct {
	Address string `json:"address"`
	Expect  string `json:"expect"`
}

type dnsQuery struct {
	Resolver  string `json:"resolver"`
	Transport string `json:"transport"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Expect    string `json:"expect"`
}

type httpTarget struct {
	URL                 string `json:"url"`
	MaxRedirects        int    `json:"max_redirects"`
	Expect              string `json:"expect"`
	ExpectedRedirectURL string `json:"expected_redirect_url,omitempty"`
}

type freshResolution struct {
	Resolver     string `json:"resolver"`
	Transport    string `json:"transport"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Port         int    `json:"port"`
	Rounds       int    `json:"rounds"`
	MaxAddresses int    `json:"max_addresses"`
	IntervalMS   int    `json:"interval_ms"`
	Expect       string `json:"expect"`
}

func expectedFixtureEgress(c probeConfig) wire.EgressPolicy {
	if c.Scenario != nil && c.Scenario.Kind == "network" && c.Scenario.Network != nil && c.Scenario.Network.ExpectedEgress == "PUBLIC_INTERNET" {
		return wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET
	}
	return wire.EgressPolicy_EGRESS_POLICY_NONE
}

func validateFixtureGrants(c probeConfig, init *wire.InitContext) error {
	if init == nil || init.Grants == nil || len(init.Grants.Backends) != 0 || init.Grants.EgressPolicy != expectedFixtureEgress(c) {
		return errors.New("fixture egress expectation does not match authenticated backendless grants")
	}
	if expectedFixtureEgress(c) == wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET {
		for _, grant := range init.Grants.CoreCapabilities {
			if grant == nil || grant.Name != core.CapabilityPublicEgress {
				continue
			}
			for _, scope := range grant.ResourceScopes {
				if scope != nil && scope.GetSelector() != nil && len(scope.GetSelector().ResourceIds) == 0 {
					return nil
				}
			}
		}
		return errors.New("PUBLIC fixture requires actual scoped public egress capability")
	}
	return nil
}

func numericEndpoint(address string) bool {
	if len(address) > 192 {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	n, portErr := strconv.Atoi(port)
	return err == nil && ip.IsValid() && portErr == nil && n >= 1 && n <= 65535
}

func validDNSName(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func validDNSFields(resolver, transport, name, kind string) bool {
	return numericEndpoint(resolver) && (transport == "udp" || transport == "tcp") && validDNSName(name) && (kind == "A" || kind == "AAAA")
}

func parseProbeURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 2048 {
		return nil, errors.New("invalid bounded probe URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.Host == "" || u.Hostname() == "" || len(u.Hostname()) > 253 || u.Opaque != "" || u.Fragment != "" {
		return nil, errors.New("invalid bounded probe URL")
	}
	if port := u.Port(); port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid probe URL port")
		}
	}
	return u, nil
}

// Hash the fragmentless net/url serialization, treating an empty path as "/".
// Preserve escaped path/query spelling; do not expose URL contents in reports.
func effectiveProbeURL(u *url.URL) string {
	effective := *u
	effective.Fragment, effective.RawFragment = "", ""
	if effective.Path == "" {
		effective.Path, effective.RawPath = "/", ""
	}
	return effective.String()
}

func probeURLHash(u *url.URL) string {
	digest := sha256.Sum256([]byte(effectiveProbeURL(u)))
	return hex.EncodeToString(digest[:])
}

func validateNetwork(c *networkConfig) error {
	invalid := errors.New("invalid bounded network scenario")
	if c == nil || c.ExpectedEgress != "NONE" && c.ExpectedEgress != "PUBLIC_INTERNET" || c.OperationTimeoutMS < 1 || c.OperationTimeoutMS > 10000 || len(c.TCP) > 16 || len(c.DNS) > 8 || len(c.HTTP) > 2 || len(c.Fresh) > 2 || len(c.TCP)+len(c.DNS)+len(c.HTTP)+len(c.Fresh) == 0 {
		return invalid
	}
	for _, q := range c.TCP {
		if !numericEndpoint(q.Address) || q.Expect != "connect" && q.Expect != "deny" {
			return invalid
		}
	}
	for _, q := range c.DNS {
		if !validDNSFields(q.Resolver, q.Transport, q.Name, q.Type) || q.Expect != "response" && q.Expect != "deny" {
			return invalid
		}
	}
	for _, q := range c.HTTP {
		if _, err := parseProbeURL(q.URL); err != nil || q.MaxRedirects < 0 || q.MaxRedirects > 3 || q.Expect != "response" && q.Expect != "deny" {
			return invalid
		}
		if q.ExpectedRedirectURL != "" {
			u, err := parseProbeURL(q.ExpectedRedirectURL)
			if err != nil || !numericEndpoint(u.Host) || effectiveProbeURL(u) != q.ExpectedRedirectURL || q.MaxRedirects < 1 || q.Expect != "deny" {
				return invalid
			}
		}
	}
	for _, q := range c.Fresh {
		if !validDNSFields(q.Resolver, q.Transport, q.Name, q.Type) || q.Port < 1 || q.Port > 65535 || q.Rounds < 2 || q.Rounds > 3 || q.MaxAddresses < 1 || q.MaxAddresses > 4 || q.IntervalMS < 0 || q.IntervalMS > 1000 || q.Expect != "connect" && q.Expect != "deny" && q.Expect != "connect_then_deny" {
			return invalid
		}
	}
	return nil
}

func networkProbe(ctx context.Context, c *networkConfig, p *probeSession) error {
	p.record("network", "observations-not-enforcement-verdicts", nil, map[string]any{"expected_egress": c.ExpectedEgress, "operation_timeout_ms": c.OperationTimeoutMS})
	for i, q := range c.TCP {
		if err := ctx.Err(); err != nil {
			return err
		}
		tcpObservation(ctx, c.OperationTimeoutMS, q.Address, q.Expect, p, map[string]any{"target_index": i})
	}
	for i, q := range c.DNS {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Denied/inconclusive operations must not skip remaining controls.
		_, _ = dnsObservation(ctx, c.OperationTimeoutMS, q, 4, p, map[string]any{"query_index": i})
	}
	for i, q := range c.HTTP {
		if err := ctx.Err(); err != nil {
			return err
		}
		httpObservation(ctx, c.OperationTimeoutMS, q, i, p)
	}
	for i, q := range c.Fresh {
		for round := range q.Rounds {
			if err := ctx.Err(); err != nil {
				return err
			}
			if round > 0 {
				if err := waitUntil(ctx, time.Now().Add(time.Duration(q.IntervalMS)*time.Millisecond)); err != nil {
					return err
				}
			}
			query := dnsQuery{Resolver: q.Resolver, Transport: q.Transport, Name: q.Name, Type: q.Type, Expect: "response"}
			ips, err := dnsObservation(ctx, c.OperationTimeoutMS, query, q.MaxAddresses, p, map[string]any{"fresh_index": i, "round": round})
			if err != nil {
				continue
			}
			if len(ips) == 0 {
				p.record("network-fresh", "no-selected-addresses-no-connect", errors.New("DNS returned no usable bounded addresses"), map[string]any{"fresh_index": i, "round": round})
			}
			for _, ip := range ips {
				if err := ctx.Err(); err != nil {
					return err
				}
				expected := q.Expect
				if expected == "connect_then_deny" {
					expected = "deny"
					if round == 0 {
						expected = "connect"
					}
				}
				tcpObservation(ctx, c.OperationTimeoutMS, net.JoinHostPort(ip, strconv.Itoa(q.Port)), expected, p, map[string]any{"fresh_index": i, "round": round})
			}
		}
	}
	return ctx.Err()
}

func tcpObservation(ctx context.Context, ms int, address, expect string, p *probeSession, data map[string]any) {
	bounded, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
	defer cancel()
	data["address"], data["expected"] = address, expect
	conn, err := (&net.Dialer{}).DialContext(bounded, "tcp", address)
	data["connected"] = conn != nil && err == nil
	if conn != nil {
		data["local_address"], data["remote_address"] = conn.LocalAddr().String(), conn.RemoteAddr().String()
		_ = conn.Close()
	}
	p.record("network-tcp", "connect-returned", networkError(bounded, err), data)
}

func networkError(ctx context.Context, err error) error {
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return context.DeadlineExceeded
	}
	return err
}

var dnsSequence atomic.Uint32

type dnsResult struct {
	addresses []string
	data      map[string]any
}

func dnsObservation(ctx context.Context, ms int, q dnsQuery, maxAddresses int, p *probeSession, data map[string]any) ([]string, error) {
	bounded, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
	defer cancel()
	result, err := queryDNS(bounded, q, maxAddresses)
	data["resolver"], data["transport"], data["query_type"], data["expected"] = q.Resolver, q.Transport, q.Type, q.Expect
	for key, value := range result.data {
		data[key] = value
	}
	p.record("network-dns", "query-returned", networkError(bounded, err), data)
	return result.addresses, err
}

func queryDNS(ctx context.Context, q dnsQuery, maxAddresses int) (dnsResult, error) {
	result := dnsResult{data: map[string]any{"received_response": false}}
	name, err := dnsmessage.NewName(strings.TrimSuffix(q.Name, ".") + ".")
	if err != nil {
		return result, errors.New("invalid probe DNS question")
	}
	kind := dnsmessage.TypeA
	if q.Type == "AAAA" {
		kind = dnsmessage.TypeAAAA
	}
	id := uint16(dnsSequence.Add(1))
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
	packet, err := message.Pack()
	if err != nil {
		return result, errors.New("probe DNS encoding failed")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, q.Transport, q.Resolver)
	if err != nil {
		return result, err
	}
	defer conn.Close()
	result.data["local_address"], result.data["remote_address"] = conn.LocalAddr().String(), conn.RemoteAddr().String()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return result, err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if q.Transport == "tcp" {
		framed := make([]byte, 2+len(packet))
		binary.BigEndian.PutUint16(framed, uint16(len(packet)))
		copy(framed[2:], packet)
		packet = framed
	}
	written, err := conn.Write(packet)
	result.data["sent_bytes"] = written
	if err != nil {
		return result, err
	}
	if written != len(packet) {
		return result, errors.New("short DNS query write")
	}
	response := make([]byte, 4096)
	var received int
	if q.Transport == "tcp" {
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return result, err
		}
		n := int(binary.BigEndian.Uint16(prefix[:]))
		if n < 12 || n > len(response) {
			result.data["response_declared_bytes"] = n
			return result, errors.New("DNS response exceeds fixture bound or is malformed")
		}
		received, err = io.ReadFull(conn, response[:n])
	} else {
		udp, ok := conn.(*net.UDPConn)
		if !ok {
			return result, errors.New("DNS UDP transport unavailable")
		}
		var flags int
		received, _, flags, _, err = udp.ReadMsgUDP(response, nil)
		if flags&unix.MSG_TRUNC != 0 {
			result.data["receive_truncated_by_fixture_buffer"] = true
			err = errors.New("DNS datagram exceeds fixture bound")
		}
	}
	result.data["received_bytes"] = received
	if err != nil {
		return result, err
	}
	var reply dnsmessage.Message
	if reply.Unpack(response[:received]) != nil || reply.ID != id || !reply.Response || len(reply.Questions) != 1 || !strings.EqualFold(reply.Questions[0].Name.String(), name.String()) || reply.Questions[0].Type != kind || reply.Questions[0].Class != dnsmessage.ClassINET {
		return result, errors.New("DNS response does not match probe question")
	}
	result.data["received_response"], result.data["rcode"], result.data["dns_truncated"], result.data["answer_records"] = true, int(reply.RCode), reply.Truncated, len(reply.Answers)
	if reply.Truncated {
		return result, errors.New("truncated DNS response requires an explicit TCP probe")
	}
	seen := make(map[string]bool)
	for _, answer := range reply.Answers {
		var ip string
		switch value := answer.Body.(type) {
		case *dnsmessage.AResource:
			if kind == dnsmessage.TypeA {
				ip = netip.AddrFrom4(value.A).String()
			}
		case *dnsmessage.AAAAResource:
			if kind == dnsmessage.TypeAAAA {
				ip = netip.AddrFrom16(value.AAAA).String()
			}
		}
		if ip != "" && !seen[ip] && len(result.addresses) < maxAddresses {
			seen[ip] = true
			result.addresses = append(result.addresses, ip)
		}
	}
	result.data["selected_addresses"] = result.addresses
	return result, nil
}

// Only fixed error categories leave the fixture, never URLs or error strings.
func httpErrorCategory(ctx context.Context, err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(networkError(ctx, err), context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var dns *net.DNSError
	var operation *net.OpError
	switch {
	case errors.As(err, &unknown):
		return "tls-unknown-authority"
	case errors.As(err, &hostname):
		return "tls-hostname"
	case errors.As(err, &invalid):
		return "tls-certificate-invalid"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &operation):
		return "network-operation"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "unexpected-eof"
	default:
		return "http-operation"
	}
}

func httpDialObservation(ctx context.Context, network, address string, index, hop int, p *probeSession, requestHash string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid HTTP dial address")
	}
	var ips []netip.Addr
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		ips = []netip.Addr{ip}
	} else {
		// Use the guest's real resolver contract, not an IP-class policy inside
		// the fixture. Limit connect attempts even if DNS returns many answers.
		ips, err = (&net.Resolver{PreferGo: true}).LookupNetIP(ctx, "ip", host)
		selected := make([]string, 0, min(len(ips), 4))
		for _, ip := range ips[:min(len(ips), 4)] {
			selected = append(selected, ip.String())
		}
		data := map[string]any{"request_index": index, "hop": hop, "hostname": host, "address_count": len(ips), "selected_addresses": selected}
		var dns *net.DNSError
		if errors.As(err, &dns) {
			data["dns_not_found"], data["dns_timeout"], data["dns_temporary"] = dns.IsNotFound, dns.IsTimeout, dns.IsTemporary
			if numericEndpoint(dns.Server) {
				data["dns_server"] = dns.Server
			}
		}
		p.record("network-http", "guest-resolver-returned", networkError(ctx, err), data)
		if err != nil {
			return nil, err
		}
	}
	for _, ip := range ips[:min(len(ips), 4)] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target := net.JoinHostPort(ip.String(), port)
		conn, dialErr := (&net.Dialer{}).DialContext(ctx, network, target)
		data := map[string]any{"request_index": index, "hop": hop, "request_url_sha256": requestHash, "actual_address": target, "connected": conn != nil && dialErr == nil}
		if conn != nil {
			data["local_address"], data["remote_address"] = conn.LocalAddr().String(), conn.RemoteAddr().String()
		}
		p.record("network-http", "actual-dial-returned", networkError(ctx, dialErr), data)
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	if err == nil {
		err = errors.New("HTTP resolver returned no addresses")
	}
	return nil, err
}

func httpObservation(ctx context.Context, ms int, q httpTarget, index int, p *probeSession) {
	current, err := parseProbeURL(q.URL)
	if err != nil {
		p.record("network-http", "invalid-url", err, map[string]any{"request_index": index})
		return
	}
	for hop := range q.MaxRedirects + 1 {
		if ctx.Err() != nil {
			return
		}
		bounded, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192, ResponseHeaderTimeout: time.Duration(ms) * time.Millisecond}
		requestHash := probeURLHash(current)
		transport.DialContext = func(c context.Context, network, address string) (net.Conn, error) {
			return httpDialObservation(c, network, address, index, hop, p, requestHash)
		}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		request, requestErr := http.NewRequestWithContext(bounded, http.MethodGet, effectiveProbeURL(current), nil)
		if requestErr != nil {
			cancel()
			p.record("network-http", "request-construction-failed", errors.New("invalid probe request"), map[string]any{"request_index": index, "hop": hop})
			return
		}
		response, err := client.Do(request)
		data := map[string]any{"request_index": index, "hop": hop, "request_url_sha256": requestHash, "scheme": current.Scheme, "host": current.Host, "expected_final": q.Expect, "received_response": response != nil && err == nil, "error_category": httpErrorCategory(bounded, err)}
		var next *url.URL
		if response != nil {
			data["status"] = response.StatusCode
			if response.StatusCode == 301 || response.StatusCode == 302 || response.StatusCode == 303 || response.StatusCode == 307 || response.StatusCode == 308 {
				next, requestErr = response.Location()
				data["has_redirect_location"] = requestErr == nil
				if requestErr == nil {
					data["redirect_url_sha256"] = probeURLHash(next)
				}
			}
			// Do not read or log any response body, credentials, cookies, Location
			// value, path, query, headers, or raw errors. New hops use fresh clients.
			_ = response.Body.Close()
		}
		p.record("network-http", "response-returned", networkError(bounded, err), data)
		transport.CloseIdleConnections()
		cancel()
		if err != nil || next == nil {
			return
		}
		if hop == q.MaxRedirects {
			p.record("network-http", "redirect-hop-bound-reached", nil, map[string]any{"request_index": index, "hop": hop})
			return
		}
		current, err = parseProbeURL(effectiveProbeURL(next))
		if err != nil {
			p.record("network-http", "redirect-url-rejected", err, map[string]any{"request_index": index, "hop": hop})
			return
		}
		// No fixture IP allow/deny check: the next request really attempts the
		// redirect destination and must encounter the host's actual policy.
	}
}
