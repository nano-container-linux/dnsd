package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddCERTRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "cert", Type: "CERT", CertType: 1, KeyTag: 1234, Algo: 8, Cert: "QUJDRA=="}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	cert := requireSingleRR[*dns.CERT](t, runtime, dns.TypeCERT, owner)
	if cert.Hdr.Name != owner || cert.Type != 1 || cert.KeyTag != 1234 || cert.Algorithm != 8 || cert.Certificate != "QUJDRA==" {
		t.Fatalf("unexpected CERT record: %+v", cert)
	}
}

func TestAddCERTRecordMissingFields(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "cert", Type: "CERT", Algo: 8, Cert: "QUJDRA=="}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for incomplete CERT record")
	}
}
