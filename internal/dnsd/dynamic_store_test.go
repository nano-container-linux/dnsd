package dnsd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestSubmitDynamicPayload_PersistsAndAppliesAnswers(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &RuntimeConfig{
		ConfigDir: tmpDir,
		Answers:   map[uint16]map[string][]dns.RR{},
	}

	payload := `
record "web" {
  type = "A"
  ip   = "192.0.2.10"
}

zone "example.com." {
  records = ["web"]
}
`

	id, path, err := submitDynamicPayload(cfg, payload)
	if err != nil {
		t.Fatalf("submitDynamicPayload returned error: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty id")
	}
	if path == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Dir(path) != filepath.Join(tmpDir, "dyndns") {
		t.Fatalf("unexpected persistence directory: %s", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected persisted file to exist: %v", err)
	}

	owner := normalizeName("web.example.com.")
	aRecords := cfg.Answers[dns.TypeA][owner]
	if len(aRecords) != 1 {
		t.Fatalf("expected one A record for %s, got %d", owner, len(aRecords))
	}
}
