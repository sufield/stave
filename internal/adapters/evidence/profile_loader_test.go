package evidence

import (
	"os"
	"path/filepath"
	"testing"

	coreevidence "github.com/sufield/stave/internal/core/evidence"
)

func TestLoadEmbeddedProfiles_NoError(t *testing.T) {
	profiles, err := LoadEmbeddedProfiles()
	if err != nil {
		t.Fatalf("LoadEmbeddedProfiles: %v", err)
	}
	if len(profiles) == 0 {
		t.Fatal("expected at least one profile")
	}
}

func TestLoadProfile_ByID(t *testing.T) {
	p, err := LoadProfile("cis_aws_v3.0")
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if p.ID != "cis_aws_v3.0" {
		t.Errorf("ID = %q, want cis_aws_v3.0", p.ID)
	}
	if p.FrameworkKey != "cis_aws_v3.0" {
		t.Errorf("FrameworkKey = %q", p.FrameworkKey)
	}
}

func TestLoadProfile_NotFound(t *testing.T) {
	_, err := LoadProfile("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
}

func TestParseProfile_ThresholdRoundTrip(t *testing.T) {
	yaml := `
id: test
name: Test
version: "1.0"
framework_key: test
requirements:
  - id: R1
    description: Test all
    controls: [CTL.A]
    pass_threshold: all
  - id: R2
    description: Test any
    controls: [CTL.B]
    pass_threshold: any
  - id: R3
    description: Test percent
    controls: [CTL.C]
    pass_threshold: "percent:80"
  - id: R4
    description: Test default
    controls: [CTL.D]
`
	p, err := parseProfile([]byte(yaml), "test.yaml")
	if err != nil {
		t.Fatalf("parseProfile: %v", err)
	}
	if len(p.Requirements) != 4 {
		t.Fatalf("len = %d, want 4", len(p.Requirements))
	}
	if p.Requirements[0].PassThreshold.Mode != coreevidence.ThresholdAll {
		t.Errorf("R1 threshold = %v", p.Requirements[0].PassThreshold.Mode)
	}
	if p.Requirements[1].PassThreshold.Mode != coreevidence.ThresholdAny {
		t.Errorf("R2 threshold = %v", p.Requirements[1].PassThreshold.Mode)
	}
	if p.Requirements[2].PassThreshold.Mode != coreevidence.ThresholdPercent {
		t.Errorf("R3 threshold mode = %v", p.Requirements[2].PassThreshold.Mode)
	}
	if p.Requirements[2].PassThreshold.Percent != 80 {
		t.Errorf("R3 percent = %v", p.Requirements[2].PassThreshold.Percent)
	}
	// R4 has no pass_threshold — defaults to all
	if p.Requirements[3].PassThreshold.Mode != coreevidence.ThresholdAll {
		t.Errorf("R4 default threshold = %v", p.Requirements[3].PassThreshold.Mode)
	}
}

func TestLoadEmbeddedProfiles_AllFivePresent(t *testing.T) {
	profiles, err := LoadEmbeddedProfiles()
	if err != nil {
		t.Fatalf("LoadEmbeddedProfiles: %v", err)
	}
	if len(profiles) < 5 {
		t.Fatalf("len = %d, want at least 5", len(profiles))
	}

	expected := map[string]int{
		"hipaa":            17,
		"soc2":             14,
		"pci_dss_v4.0":     35,
		"fedramp_moderate": 40,
		"cis_aws_v3.0":     58,
	}
	byID := make(map[string]*coreevidence.FrameworkProfile, len(profiles))
	for _, p := range profiles {
		byID[p.ID] = p
	}
	for id, wantReqs := range expected {
		p, ok := byID[id]
		if !ok {
			t.Fatalf("missing expected embedded profile %q", id)
		}
		if len(p.Requirements) != wantReqs {
			t.Errorf("%s: %d requirements, want %d", p.ID, len(p.Requirements), wantReqs)
		}
		if p.FrameworkKey == "" {
			t.Errorf("%s: empty FrameworkKey", p.ID)
		}
	}
}

func TestLoadProfileFromFile(t *testing.T) {
	yaml := `
id: custom_dora
name: "DORA ICT Risk Management"
version: "2025-01"
framework_key: custom_dora
requirements:
  - id: "ART5.1"
    description: "ICT risk management framework"
    section: "Article 5"
    controls:
      - CTL.CLOUDTRAIL.ENABLED.001
      - CTL.CONFIG.RECORDER.001
    pass_threshold: all
`
	path := filepath.Join(t.TempDir(), "dora.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	profile, err := LoadProfileFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if profile.ID != "custom_dora" {
		t.Errorf("ID = %q, want custom_dora", profile.ID)
	}
	if len(profile.Requirements) != 1 {
		t.Fatalf("requirements = %d, want 1", len(profile.Requirements))
	}
	if len(profile.Requirements[0].ControlIDs) != 2 {
		t.Errorf("controls = %d, want 2", len(profile.Requirements[0].ControlIDs))
	}
}

func TestLoadProfileFromFile_NotFound(t *testing.T) {
	_, err := LoadProfileFromFile("/nonexistent/profile.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestParseProfile_MissingID(t *testing.T) {
	yaml := `
name: No ID
version: "1.0"
framework_key: test
requirements: []
`
	_, err := parseProfile([]byte(yaml), "bad.yaml")
	if err == nil {
		t.Error("expected error for missing ID")
	}
}
