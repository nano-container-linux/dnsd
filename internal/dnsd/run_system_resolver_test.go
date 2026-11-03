package dnsd

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestResolverAddrsFromClientConfig_DefaultPort(t *testing.T) {
	cfg := &dns.ClientConfig{
		Servers: []string{"8.8.8.8", "1.1.1.1"},
		Port:    "53",
	}
	addrs, err := resolverAddrsFromClientConfig(cfg, 0)
	if err != nil {
		t.Fatalf("resolverAddrsFromClientConfig() error = %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 resolver addrs, got %d", len(addrs))
	}
	if addrs[0] != net.JoinHostPort("8.8.8.8", "53") {
		t.Fatalf("unexpected addr[0]: %s", addrs[0])
	}
	if addrs[1] != net.JoinHostPort("1.1.1.1", "53") {
		t.Fatalf("unexpected addr[1]: %s", addrs[1])
	}
}

func TestResolverAddrsFromClientConfig_PortOverride(t *testing.T) {
	cfg := &dns.ClientConfig{
		Servers: []string{"8.8.8.8"},
		Port:    "53",
	}
	addrs, err := resolverAddrsFromClientConfig(cfg, 5353)
	if err != nil {
		t.Fatalf("resolverAddrsFromClientConfig() error = %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 resolver addr, got %d", len(addrs))
	}
	if addrs[0] != net.JoinHostPort("8.8.8.8", "5353") {
		t.Fatalf("unexpected overridden addr: %s", addrs[0])
	}
}

func TestResolverAddrsFromClientConfig_NoServers(t *testing.T) {
	cfg := &dns.ClientConfig{Port: "53"}
	_, err := resolverAddrsFromClientConfig(cfg, 0)
	if err == nil {
		t.Fatal("expected resolverAddrsFromClientConfig to fail with no servers")
	}
	if !strings.Contains(err.Error(), "no resolver nameservers") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSplitPercent(t *testing.T) {
	parts := splitPercent(100, 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}
	var total uint16
	for _, p := range parts {
		total += p
	}
	if total != 100 {
		t.Fatalf("expected total 100, got %d", total)
	}
}
