package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddRPRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "RP", Mbox: "hostmaster", TxtDName: "rp-info"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	rp := requireSingleRR[*dns.RP](t, runtime, dns.TypeRP, owner)
	if rp.Hdr.Name != owner || rp.Mbox != "hostmaster.example.com." || rp.Txt != "rp-info.example.com." {
		t.Fatalf("unexpected RP record: %+v", rp)
	}
}

func TestAddRPRecordMissingFields(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "RP", Mbox: "hostmaster"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for incomplete RP record")
	}
}
