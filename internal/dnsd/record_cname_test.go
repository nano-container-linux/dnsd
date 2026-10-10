package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddCNAMERecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "www", Type: "CNAME", CNAME: "registry"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	c := requireSingleRR[*dns.CNAME](t, runtime, dns.TypeCNAME, owner)
	if c.Hdr.Name != owner || c.Target != "registry.example.com." || c.Hdr.Ttl != 3600 {
		t.Fatalf("unexpected CNAME record: %+v", c)
	}
}

func TestAddCNAMERecordMissingTarget(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "www", Type: "CNAME"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for missing CNAME target")
	}
}
