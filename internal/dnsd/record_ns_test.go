package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddNSRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "NS", NS: "ns1"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	ns := requireSingleRR[*dns.NS](t, runtime, dns.TypeNS, owner)
	if ns.Hdr.Name != owner || ns.Ns != "ns1.example.com." {
		t.Fatalf("unexpected NS record: %+v", ns)
	}
}

func TestAddNSRecordMissingTarget(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "NS"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for missing NS target")
	}
}
