package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddMXRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "MX", Exchange: "mail", Priority: 10}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	mx := requireSingleRR[*dns.MX](t, runtime, dns.TypeMX, owner)
	if mx.Hdr.Name != owner || mx.Preference != 10 || mx.Mx != "mail.example.com." {
		t.Fatalf("unexpected MX record: %+v", mx)
	}
}

func TestAddMXRecordMissingExchange(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "@", Type: "MX", Priority: 10}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for missing MX exchange")
	}
}
