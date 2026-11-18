package dnsd

import "testing"

func TestAddRecordAnswersUnsupportedType(t *testing.T) {
	runtime := newTestRuntimeConfig()
	err := addRecordAnswers(runtime, RecordConfig{ID: "bad", Type: "BOGUS"}, "example.com.")
	if err == nil {
		t.Fatal("expected error for unsupported record type")
	}
}
