package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddPTRRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "2", Type: "PTR", PTR: "registry.example.com."}
	zone := "2.0.168.192.in-addr.arpa."
	if err := addRecordAnswers(runtime, rec, zone); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, zone)
	ptr := requireSingleRR[*dns.PTR](t, runtime, dns.TypePTR, owner)
	if ptr.Hdr.Name != owner || ptr.Ptr != "registry.example.com." {
		t.Fatalf("unexpected PTR record: %+v", ptr)
	}
}

func TestAddPTRRecordMissingTarget(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "2", Type: "PTR"}
	if err := addRecordAnswers(runtime, rec, "2.0.168.192.in-addr.arpa."); err == nil {
		t.Fatal("expected error for missing PTR target")
	}
}
