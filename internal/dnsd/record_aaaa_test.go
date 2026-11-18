package dnsd

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestAddAAAARecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "v6", Type: "AAAA", IP6: "2001:db8::1", TTL: 300}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	aaaa := requireSingleRR[*dns.AAAA](t, runtime, dns.TypeAAAA, owner)
	if aaaa.Hdr.Name != owner || aaaa.Hdr.Ttl != 300 || !aaaa.AAAA.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("unexpected AAAA record: %+v", aaaa)
	}
}

func TestAddAAAARecordInvalidIP(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "bad-aaaa", Type: "AAAA", IP6: "192.168.0.1"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for invalid AAAA record IP")
	}
}
