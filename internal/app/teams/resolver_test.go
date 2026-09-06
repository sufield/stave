package teams

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func testManifest() *Manifest {
	return &Manifest{
		OwnerTagKey:    "team",
		FallbackTagKey: "owner",
		Teams: []Team{
			{ID: "payments", DisplayName: "Payments Team", Contact: "pay@example.com",
				ResourcePatterns: []string{"arn:aws:s3:::payments-*"}},
			{ID: "data", DisplayName: "Data Team", Contact: "data@example.com",
				ControlOwnership: []kernel.ControlID{"CTL.IAM.NEP.*"}},
			{ID: "platform", DisplayName: "Platform Team", IsDefault: true},
		},
	}
}

func TestResolveOwner_TagMatch(t *testing.T) {
	m := testManifest()
	result := m.ResolveOwner(map[string]string{"team": "payments"}, "arn:aws:s3:::anything", kernel.ControlID("CTL.S3.PUBLIC.001"))
	if result.TeamID != "payments" {
		t.Errorf("team = %q, want payments", result.TeamID)
	}
	if result.ResolutionPath != "tag" {
		t.Errorf("path = %q, want tag", result.ResolutionPath)
	}
}

func TestResolveOwner_FallbackTag(t *testing.T) {
	m := testManifest()
	result := m.ResolveOwner(map[string]string{"owner": "data"}, "arn:any", kernel.ControlID("CTL.S3.001"))
	if result.TeamID != "data" {
		t.Errorf("team = %q, want data", result.TeamID)
	}
	if result.ResolutionPath != "fallback_tag" {
		t.Errorf("path = %q, want fallback_tag", result.ResolutionPath)
	}
}

func TestResolveOwner_ARNPattern(t *testing.T) {
	m := testManifest()
	result := m.ResolveOwner(nil, "arn:aws:s3:::payments-checkout", kernel.ControlID("CTL.S3.001"))
	if result.TeamID != "payments" {
		t.Errorf("team = %q, want payments", result.TeamID)
	}
	if result.ResolutionPath != "arn_pattern" {
		t.Errorf("path = %q, want arn_pattern", result.ResolutionPath)
	}
}

func TestResolveOwner_ControlOwnership(t *testing.T) {
	m := testManifest()
	result := m.ResolveOwner(nil, "arn:any", kernel.ControlID("CTL.IAM.NEP.ADMIN.001"))
	if result.TeamID != "data" {
		t.Errorf("team = %q, want data", result.TeamID)
	}
	if result.ResolutionPath != "control_ownership" {
		t.Errorf("path = %q, want control_ownership", result.ResolutionPath)
	}
}

func TestResolveOwner_Default(t *testing.T) {
	m := testManifest()
	result := m.ResolveOwner(nil, "arn:aws:ec2::123:instance/unknown", kernel.ControlID("CTL.EC2.001"))
	if result.TeamID != "platform" {
		t.Errorf("team = %q, want platform (default)", result.TeamID)
	}
	if result.ResolutionPath != "default" {
		t.Errorf("path = %q, want default", result.ResolutionPath)
	}
}

func TestResolveOwner_Unassigned(t *testing.T) {
	m := &Manifest{OwnerTagKey: "team", FallbackTagKey: "owner", Teams: []Team{
		{ID: "only-team", ResourcePatterns: []string{"arn:specific"}},
	}}
	result := m.ResolveOwner(nil, "arn:other", kernel.ControlID("CTL.X"))
	if result.TeamID != "unassigned" {
		t.Errorf("team = %q, want unassigned", result.TeamID)
	}
}

func TestLoadManifest(t *testing.T) {
	yaml := `
schema_version: "1"
owner_tag_key: "team"
teams:
  - id: payments
    display_name: "Payments"
    resource_patterns:
      - "arn:aws:s3:::pay-*"
  - id: platform
    display_name: "Platform"
    is_default: true
`
	path := filepath.Join(t.TempDir(), "teams.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Teams) != 2 {
		t.Errorf("teams = %d, want 2", len(m.Teams))
	}
	if m.OwnerTagKey != "team" {
		t.Errorf("owner_tag_key = %q, want team", m.OwnerTagKey)
	}
}

func TestLoadManifest_Defaults(t *testing.T) {
	yaml := `teams: [{id: a}]`
	path := filepath.Join(t.TempDir(), "teams.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.OwnerTagKey != "team" {
		t.Errorf("default owner_tag_key = %q, want team", m.OwnerTagKey)
	}
	if m.FallbackTagKey != "owner" {
		t.Errorf("default fallback_tag_key = %q, want owner", m.FallbackTagKey)
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, value string
		want           bool
	}{
		{"CTL.IAM.NEP.*", "CTL.IAM.NEP.ADMIN.001", true},
		{"CTL.IAM.NEP.*", "CTL.S3.PUBLIC.001", false},
		{"arn:aws:s3:::payments-*", "arn:aws:s3:::payments-checkout", true},
		{"arn:aws:s3:::payments-*", "arn:aws:s3:::data-bucket", false},
		{"exact", "exact", true},
		{"exact", "other", false},
	}
	for _, tt := range tests {
		got := globMatch(tt.pattern, tt.value)
		if got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}
