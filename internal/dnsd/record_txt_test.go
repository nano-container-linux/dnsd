package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddTXTRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "txt", Type: "TXT", Text: "v=spf1", Texts: []string{"include:example.com", "~all"}}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	txt := requireSingleRR[*dns.TXT](t, runtime, dns.TypeTXT, owner)
	if txt.Hdr.Name != owner || len(txt.Txt) != 3 || txt.Txt[0] != "v=spf1" {
		t.Fatalf("unexpected TXT record: %+v", txt)
	}
}

func TestAddTXTRecordMissingText(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "txt", Type: "TXT"}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for missing TXT payload")
	}
}
