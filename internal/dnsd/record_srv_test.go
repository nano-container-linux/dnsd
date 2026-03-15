package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddSRVRecord(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "_svc._tcp", Type: "SRV", Priority: 10, Weight: 20, Port: 443, Targets: []SRVTargetConfig{{Name: "registry"}}}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	srv := requireSingleRR[*dns.SRV](t, runtime, dns.TypeSRV, owner)
	if srv.Hdr.Name != owner || srv.Port != 443 || srv.Priority != 10 || srv.Weight != 20 || srv.Target != "registry.example.com." {
		t.Fatalf("unexpected SRV record: %+v", srv)
	}
}

func TestAddSRVRecordMultipleTargets(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "_oci._tcp", Type: "SRV", Priority: 10, Weight: 60, Port: 5000, Targets: []SRVTargetConfig{{Name: "registry"}, {Name: "ghcr.io.", Port: ptrUint16(443)}}}
	if err := addRecordAnswers(runtime, rec, "example.com."); err != nil {
		t.Fatalf("addRecordAnswers() error = %v", err)
	}
	owner := fqdnInZone(rec.ID, "example.com.")
	rrs := runtime.Answers[dns.TypeSRV][owner]
	if len(rrs) != 2 {
		t.Fatalf("expected 2 SRV records, got %d", len(rrs))
	}
	first := rrs[0].(*dns.SRV)
	second := rrs[1].(*dns.SRV)
	if first.Target != "registry.example.com." || first.Port != 5000 {
		t.Fatalf("unexpected first SRV: %+v", first)
	}
	if second.Target != "ghcr.io." || second.Port != 443 {
		t.Fatalf("unexpected second SRV: %+v", second)
	}
}

func TestAddSRVRecordMissingTargets(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "_bad._tcp", Type: "SRV", Port: 443}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for missing SRV targets")
	}
}

func TestAddSRVRecordInvalidPort(t *testing.T) {
	runtime := newTestRuntimeConfig()
	rec := RecordConfig{ID: "_bad._tcp", Type: "SRV", Targets: []SRVTargetConfig{{Name: "registry"}}}
	if err := addRecordAnswers(runtime, rec, "example.com."); err == nil {
		t.Fatal("expected error for invalid SRV port")
	}
}
