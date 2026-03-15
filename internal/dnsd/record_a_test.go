package dnsd

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestAddARecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "registry", Type: "A", IP: "192.168.64.2", TTL: 120}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	a := requireSingleRR[*dns.A](t, runtime, dns.TypeA, owner)
	if a.Hdr.Name != owner || a.Hdr.Ttl != 120 || !a.A.Equal(net.ParseIP("192.168.64.2").To4()) {
		t.Fatalf("unexpected A record: %+v", a)
	}
}

func TestAddARecordInvalidIP(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "bad-a", Type: "A", IP: "not-an-ip"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for invalid A record IP")
	}
}
