package dnsd

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

type testResponseWriter struct {
	local  net.Addr
	remote net.Addr
	msg    *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr       { return w.local }
func (w *testResponseWriter) RemoteAddr() net.Addr      { return w.remote }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) WriteMsg(m *dns.Msg) error {
	copyMsg := new(dns.Msg)
	*copyMsg = *m
	w.msg = copyMsg
	return nil
}

func mustRR(t *testing.T, rr string) dns.RR {
	t.Helper()
	parsed, err := dns.NewRR(rr)
	if err != nil {
		t.Fatalf("dns.NewRR(%q) error = %v", rr, err)
	}
	return parsed
}

func TestResolveListenAddrsParsesBindACLs(t *testing.T) {
	binds, err := resolveListenAddrs(DNSConfig{
		Binds: []BindConfig{{
			Addr: "127.0.0.1",
			Port: 8053,
			Query: &BindAccessConfig{
				Allow: []string{"192.0.2.0/24", "192.0.2.10", "2001:db8::/32", "2001:db8::1"},
				Deny:  []string{"198.51.100.0/24"},
			},
			Transfer: &BindAccessConfig{
				Allow: []string{"203.0.113.10", "2001:db8:ffff::/48"},
				Deny:  []string{"203.0.113.254"},
			},
		}},
	})
	if err != nil {
		t.Fatalf("resolveListenAddrs() error = %v", err)
	}
	if len(binds) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(binds))
	}
	if got := binds[0].Addr; got != "127.0.0.1:8053" {
		t.Fatalf("unexpected bind addr: %s", got)
	}
	if binds[0].Net != "udp" || binds[1].Net != "tcp" {
		t.Fatalf("unexpected listener nets: %s, %s", binds[0].Net, binds[1].Net)
	}
	if len(binds[0].Policy.query.allow) != 4 {
		t.Fatalf("expected 4 query allow prefixes, got %d", len(binds[0].Policy.query.allow))
	}
	if len(binds[0].Policy.transfer.allow) != 2 {
		t.Fatalf("expected 2 transfer allow prefixes, got %d", len(binds[0].Policy.transfer.allow))
	}
	if !hasPrefix(binds[0].Policy.query.allow, "192.0.2.10/32") {
		t.Fatalf("missing exact IPv4 query allow prefix: %+v", binds[0].Policy.query.allow)
	}
	if !hasPrefix(binds[0].Policy.query.allow, "2001:db8::1/128") {
		t.Fatalf("missing exact IPv6 query allow prefix: %+v", binds[0].Policy.query.allow)
	}
	if !hasPrefix(binds[0].Policy.transfer.allow, "203.0.113.10/32") {
		t.Fatalf("missing exact IPv4 transfer allow prefix: %+v", binds[0].Policy.transfer.allow)
	}
}

func TestResolveListenAddrsRejectsInvalidBindACL(t *testing.T) {
	_, err := resolveListenAddrs(DNSConfig{
		Binds: []BindConfig{{
			Addr: "127.0.0.1",
			Port: 8053,
			Query: &BindAccessConfig{
				Allow: []string{"not-an-ip"},
				Deny:  []string{},
			},
			Transfer: &BindAccessConfig{
				Allow: []string{"127.0.0.1"},
				Deny:  []string{},
			},
		}},
	})
	if err == nil {
		t.Fatal("expected resolveListenAddrs to fail for invalid ACL entry")
	}
	if got := err.Error(); got == "" || !containsAll(got, ".query.allow", "valid CIDR prefix or IP address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveListenAddrsRequiresQueryAndTransferBlocks(t *testing.T) {
	_, err := resolveListenAddrs(DNSConfig{
		Binds: []BindConfig{{
			Addr: "127.0.0.1",
			Port: 8053,
			Query: &BindAccessConfig{
				Allow: []string{"127.0.0.1"},
				Deny:  []string{},
			},
		}},
	})
	if err == nil {
		t.Fatal("expected resolveListenAddrs to fail when transfer block is missing")
	}
	if got := err.Error(); !containsAll(got, ".transfer", "required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveListenAddrsRequiresAllowAndDeny(t *testing.T) {
	_, err := resolveListenAddrs(DNSConfig{
		Binds: []BindConfig{{
			Addr: "127.0.0.1",
			Port: 8053,
			Query: &BindAccessConfig{
				Allow: []string{"127.0.0.1"},
			},
			Transfer: &BindAccessConfig{
				Allow: []string{"127.0.0.1"},
				Deny:  []string{},
			},
		}},
	})
	if err == nil {
		t.Fatal("expected resolveListenAddrs to fail when query.deny is not specified")
	}
	if got := err.Error(); !containsAll(got, ".query.deny", "must be specified") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleQueriesRefusesDisallowedRemoteIP(t *testing.T) {
	cfg := newTestRuntimeConfig()
	cfg.Answers[dns.TypeA] = map[string][]dns.RR{
		"example.com.": {mustRR(t, "example.com. 60 IN A 192.0.2.10")},
	}

	handler := handleQueries(cfg, ListenBind{
		Addr: "127.0.0.1:53",
		Net:  "udp",
		Policy: bindPolicyRuntime{
			query: bindACLRuntime{
				allow: mustPrefixes(t, "192.0.2.0/24"),
			},
		},
	})

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	writer := &testResponseWriter{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 50000},
	}

	handler(writer, msg)

	if writer.msg == nil {
		t.Fatal("expected a DNS response")
	}
	if writer.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED rcode, got %d", writer.msg.Rcode)
	}
	if len(writer.msg.Answer) != 0 {
		t.Fatalf("expected no answers for refused query, got %d", len(writer.msg.Answer))
	}
}

func TestHandleQueriesAllowsAuthorizedRemoteIP(t *testing.T) {
	cfg := newTestRuntimeConfig()
	cfg.Answers[dns.TypeA] = map[string][]dns.RR{
		"example.com.": {mustRR(t, "example.com. 60 IN A 192.0.2.10")},
	}

	handler := handleQueries(cfg, ListenBind{
		Addr: "127.0.0.1:53",
		Net:  "udp",
		Policy: bindPolicyRuntime{
			query: bindACLRuntime{
				allow: mustPrefixes(t, "192.0.2.0/24"),
			},
		},
	})

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	writer := &testResponseWriter{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 50000},
	}

	handler(writer, msg)

	if writer.msg == nil {
		t.Fatal("expected a DNS response")
	}
	if writer.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", writer.msg.Rcode)
	}
	if len(writer.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(writer.msg.Answer))
	}
}

func TestHandleQueriesDenyOverridesAllow(t *testing.T) {
	cfg := newTestRuntimeConfig()
	cfg.Answers[dns.TypeA] = map[string][]dns.RR{
		"example.com.": {mustRR(t, "example.com. 60 IN A 192.0.2.10")},
	}

	handler := handleQueries(cfg, ListenBind{
		Addr: "127.0.0.1:53",
		Net:  "udp",
		Policy: bindPolicyRuntime{
			query: bindACLRuntime{
				allow: mustPrefixes(t, "192.0.2.0/24"),
				deny:  mustPrefixes(t, "192.0.2.44"),
			},
		},
	})

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	writer := &testResponseWriter{
		local:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
		remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.44"), Port: 50000},
	}

	handler(writer, msg)

	if writer.msg == nil {
		t.Fatal("expected a DNS response")
	}
	if writer.msg.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED rcode, got %d", writer.msg.Rcode)
	}
}

func TestZoneTransferEnvelopeAXFR(t *testing.T) {
	cfg := newTestRuntimeConfig()
	cfg.Zones = []string{"example.com."}
	cfg.Answers[dns.TypeSOA] = map[string][]dns.RR{
		"example.com.": {mustRR(t, "example.com. 60 IN SOA ns1.example.com. hostmaster.example.com. 10 3600 600 86400 60")},
	}
	cfg.Answers[dns.TypeNS] = map[string][]dns.RR{
		"example.com.": {mustRR(t, "example.com. 60 IN NS ns1.example.com.")},
	}
	cfg.Answers[dns.TypeA] = map[string][]dns.RR{
		"ns1.example.com.": {mustRR(t, "ns1.example.com. 60 IN A 192.0.2.53")},
	}

	envelope, err := cfg.zoneTransferEnvelope("example.com.", dns.TypeAXFR, 0)
	if err != nil {
		t.Fatalf("zoneTransferEnvelope() error = %v", err)
	}
	if len(envelope.RR) != 4 {
		t.Fatalf("expected 4 records in AXFR envelope, got %d", len(envelope.RR))
	}
	if envelope.RR[0].Header().Rrtype != dns.TypeSOA || envelope.RR[len(envelope.RR)-1].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("expected SOA at start and end of AXFR envelope")
	}
}

func TestZoneTransferEnvelopeIXFRNoChange(t *testing.T) {
	cfg := newTestRuntimeConfig()
	cfg.Zones = []string{"example.com."}
	cfg.Answers[dns.TypeSOA] = map[string][]dns.RR{
		"example.com.": {mustRR(t, "example.com. 60 IN SOA ns1.example.com. hostmaster.example.com. 42 3600 600 86400 60")},
	}

	envelope, err := cfg.zoneTransferEnvelope("example.com.", dns.TypeIXFR, 42)
	if err != nil {
		t.Fatalf("zoneTransferEnvelope() error = %v", err)
	}
	if len(envelope.RR) != 1 {
		t.Fatalf("expected 1 record in IXFR no-change envelope, got %d", len(envelope.RR))
	}
	if envelope.RR[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("expected SOA in IXFR no-change envelope, got %s", dns.TypeToString[envelope.RR[0].Header().Rrtype])
	}
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	parsed, err := parseACLPrefixes(values, "test.rules")
	if err != nil {
		t.Fatalf("parseACLPrefixes() error = %v", err)
	}
	return parsed
}

func hasPrefix(prefixes []netip.Prefix, expected string) bool {
	for _, prefix := range prefixes {
		if prefix.String() == expected {
			return true
		}
	}
	return false
}

func containsAll(s string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(s, part) {
			return false
		}
	}
	return true
}
