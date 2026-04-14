package evidence

import (
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
	if len(profiles) != 5 {
		t.Fatalf("len = %d, want 5", len(profiles))
	}

	expected := map[string]int{
		"hipaa":            17,
		"soc2":             14,
		"pci_dss_v4.0":     35,
		"fedramp_moderate": 40,
		"cis_aws_v3.0":     58,
	}
	for _, p := range profiles {
		want, ok := expected[p.ID]
		if !ok {
			t.Errorf("unexpected profile ID %q", p.ID)
			continue
		}
		if len(p.Requirements) != want {
			t.Errorf("%s: %d requirements, want %d", p.ID, len(p.Requirements), want)
		}
		if p.FrameworkKey == "" {
			t.Errorf("%s: empty FrameworkKey", p.ID)
		}
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
