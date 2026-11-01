package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddSOARecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "SOA", MName: "ns1", RName: "hostmaster", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 60}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	soa := requireSingleRR[*dns.SOA](t, runtime, dns.TypeSOA, owner)
	if soa.Hdr.Name != owner || soa.Ns != "ns1.example.com." || soa.Mbox != "hostmaster.example.com." || soa.Serial != 1 {
		t.Fatalf("unexpected SOA record: %+v", soa)
	}
}

func TestAddSOARecordMissingFields(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "SOA", MName: "ns1"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for incomplete SOA record")
	}
}
