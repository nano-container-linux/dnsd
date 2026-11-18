package dnsd

import "testing"

func TestNormalizeDomains(t *testing.T) {
	got := normalizeDomains([]string{"Example.com", "example.com.", "lab.example.com.", ""})
	if len(got) != 2 {
		t.Fatalf("expected 2 normalized domains, got %d", len(got))
	}
	if got[0] != "example.com." || got[1] != "lab.example.com." {
		t.Fatalf("unexpected normalized domains: %#v", got)
	}
}

func TestMatchesAnyDomain(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    bool
	}{
		{name: "api.example.com.", domains: nil, want: true},
		{name: "api.example.com.", domains: []string{"example.com."}, want: true},
		{name: "example.com.", domains: []string{"example.com."}, want: true},
		{name: "api.lab.example.com.", domains: []string{"lab.example.com."}, want: true},
		{name: "api.example.net.", domains: []string{"example.com."}, want: false},
	}

	for _, tt := range tests {
		if got := matchesAnyDomain(tt.name, tt.domains); got != tt.want {
			t.Fatalf("matchesAnyDomain(%q, %#v) = %v, want %v", tt.name, tt.domains, got, tt.want)
		}
	}
}

func TestGetUpstreamGroupsSnapshotFiltersByDomain(t *testing.T) {
	cfg := &RuntimeConfig{
		UpstreamGroups: []resolvedUpstreamGroup{
			{name: "global", domains: nil},
			{name: "example", domains: []string{"example.com."}},
			{name: "lab", domains: []string{"lab.example.com."}},
		},
	}

	groups := cfg.getUpstreamGroupsSnapshot("api.lab.example.com.")
	if len(groups) != 3 {
		t.Fatalf("expected 3 matching groups, got %d", len(groups))
	}
	if groups[0].name != "global" || groups[1].name != "example" || groups[2].name != "lab" {
		t.Fatalf("unexpected group ordering/filtering: %#v", groups)
	}

	groups = cfg.getUpstreamGroupsSnapshot("api.example.net.")
	if len(groups) != 1 || groups[0].name != "global" {
		t.Fatalf("expected only global group, got %#v", groups)
	}
}
