package dnsd

import (
	"testing"

	"github.com/miekg/dns"
)

func newTestRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{Answers: map[uint16]map[string][]dns.RR{}}
}

func ptrUint16(v uint16) *uint16 { return &v }

func requireSingleRR[T any](t *testing.T, runtime *RuntimeConfig, qtype uint16, owner string) T {
	t.Helper()
	answersByType, ok := runtime.Answers[qtype]
	if !ok {
		t.Fatalf("missing answers for qtype %d", qtype)
	}
	rrs := answersByType[owner]
	if len(rrs) != 1 {
		t.Fatalf("expected 1 rr for %s, got %d", owner, len(rrs))
	}
	typed, ok := rrs[0].(T)
	if !ok {
		t.Fatalf("unexpected rr type: %T", rrs[0])
	}
	return typed
}
