package dnsd

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/miekg/dns"
)

func dyndnsDir(configDir string) string {
	return filepath.Join(configDir, "dyndns")
}

func parsePartialConfigFromBytes(filename string, payload []byte) (*PartialConfig, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(payload, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to parse dynamic payload %s: %s", filename, diags.Error())
	}

	var partial PartialConfig
	diags = gohcl.DecodeBody(file.Body, nil, &partial)
	if diags.HasErrors() {
		return nil, fmt.Errorf("failed to decode dynamic payload %s: %s", filename, diags.Error())
	}

	return &partial, nil
}

func loadDynamicConfigs(configDir string) ([]PartialConfig, error) {
	dir := dyndnsDir(configDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read dyndns directory %s: %w", dir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".hcl.b64") {
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(files)

	partials := make([]PartialConfig, 0, len(files))
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read dynamic file %s: %w", path, err)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 dynamic file %s: %w", path, err)
		}
		partial, err := parsePartialConfigFromBytes(path, decoded)
		if err != nil {
			return nil, err
		}
		partials = append(partials, *partial)
	}

	return partials, nil
}

func validateDynamicPartial(partial *PartialConfig) error {
	if len(partial.Servers) > 0 {
		return fmt.Errorf("dynamic payload must not contain server blocks")
	}
	if len(partial.Records) == 0 {
		return fmt.Errorf("dynamic payload must contain at least one record block")
	}
	if len(partial.Zones) == 0 {
		return fmt.Errorf("dynamic payload must contain at least one zone block")
	}

	recordsByID := make(map[string]RecordConfig, len(partial.Records))
	for _, rec := range partial.Records {
		if strings.TrimSpace(rec.ID) == "" {
			return fmt.Errorf("dynamic payload record id cannot be empty")
		}
		if _, exists := recordsByID[rec.ID]; exists {
			return fmt.Errorf("dynamic payload duplicate record id: %s", rec.ID)
		}
		recordsByID[rec.ID] = rec
	}

	for _, zone := range partial.Zones {
		for _, ref := range zone.Records {
			if _, ok := recordsByID[ref]; !ok {
				return fmt.Errorf("dynamic payload zone %s references unknown record id: %s", zone.Name, ref)
			}
		}
	}

	return nil
}

func buildAnswersFromPartial(partial *PartialConfig) (map[uint16]map[string][]dns.RR, error) {
	answers := map[uint16]map[string][]dns.RR{}
	runtime := &RuntimeConfig{Answers: answers}

	recordsByID := make(map[string]RecordConfig, len(partial.Records))
	for _, rec := range partial.Records {
		recordsByID[rec.ID] = rec
	}

	for _, zone := range partial.Zones {
		zoneName := normalizeName(zone.Name)
		for _, ref := range zone.Records {
			rec, ok := recordsByID[ref]
			if !ok {
				return nil, fmt.Errorf("dynamic payload zone %s references unknown record id: %s", zone.Name, ref)
			}
			if err := addRecordAnswers(runtime, rec, zoneName); err != nil {
				return nil, err
			}
		}
	}

	return answers, nil
}

func persistDynamicPayload(configDir string, payloadHCL string) (string, string, error) {
	dir := dyndnsDir(configDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("failed to create dyndns dir %s: %w", dir, err)
	}

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	filename := id + ".hcl.b64"
	path := filepath.Join(dir, filename)
	encoded := base64.StdEncoding.EncodeToString([]byte(payloadHCL))
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return "", "", fmt.Errorf("failed to persist dynamic payload %s: %w", path, err)
	}
	return id, path, nil
}

func submitDynamicPayload(cfg *RuntimeConfig, payloadHCL string) (string, string, error) {
	partial, err := parsePartialConfigFromBytes("dynamic-submit", []byte(payloadHCL))
	if err != nil {
		return "", "", err
	}
	if err := validateDynamicPartial(partial); err != nil {
		return "", "", err
	}

	answers, err := buildAnswersFromPartial(partial)
	if err != nil {
		return "", "", err
	}

	id, path, err := persistDynamicPayload(cfg.ConfigDir, payloadHCL)
	if err != nil {
		return "", "", err
	}

	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	for qtype, byName := range answers {
		if _, ok := cfg.Answers[qtype]; !ok {
			cfg.Answers[qtype] = map[string][]dns.RR{}
		}
		for owner, rrs := range byName {
			cfg.Answers[qtype][owner] = append(cfg.Answers[qtype][owner], rrs...)
		}
	}

	return id, path, nil
}
