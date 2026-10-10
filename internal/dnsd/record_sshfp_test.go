package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddSSHFPRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "host", Type: "SSHFP", Algo: 4, FPType: 2, FP: "abcdef0123456789"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	sshfp := requireSingleRR[*dns.SSHFP](t, runtime, dns.TypeSSHFP, owner)
	if sshfp.Hdr.Name != owner || sshfp.Algorithm != 4 || sshfp.Type != 2 || sshfp.FingerPrint != "abcdef0123456789" {
		t.Fatalf("unexpected SSHFP record: %+v", sshfp)
	}
}

func TestAddSSHFPRecordMissingFields(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "host", Type: "SSHFP", Algo: 4}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for incomplete SSHFP record")
	}
}
