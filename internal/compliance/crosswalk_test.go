package compliance

import (
	"strings"
	"testing"
	"time"
)

func TestResolveControlCrosswalk_UnsupportedFramework(t *testing.T) {
	raw := []byte(`
version: control_crosswalk.v1
checks:
  SC.BUILDINFO.PRESENT:
    - framework: soc2
      control_id: CC7.1
      rationale: build metadata supports evidence
`)
	// Use a name that is not a real framework and not aliased.
	_, err := ResolveControlCrosswalk(raw, []string{"made_up_framework"}, []string{"SC.BUILDINFO.PRESENT"}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "unsupported compliance framework") {
		t.Fatalf("expected unsupported framework error, got %v", err)
	}
}

// TestResolveControlCrosswalk_RejectsUnknownFrameworkInYAML pins the
// new contract from filterAndNormalizeRefs: a typo in the crosswalk
// YAML's framework field surfaces as an error rather than the entry
// being silently dropped (which used to look like missing controls).
func TestResolveControlCrosswalk_RejectsUnknownFrameworkInYAML(t *testing.T) {
	raw := []byte(`
version: control_crosswalk.v1
checks:
  SC.BUILDINFO.PRESENT:
    - framework: not_a_real_framework
      control_id: BOGUS.1
      rationale: typo in the crosswalk yaml
`)
	_, err := ResolveControlCrosswalk(raw, []string{"soc2"}, []string{"SC.BUILDINFO.PRESENT"}, time.Now().UTC())
	if err == nil {
		t.Fatal("expected error for unknown framework in yaml, got nil")
	}
	if !strings.Contains(err.Error(), "unknown framework") {
		t.Errorf("error %q should mention 'unknown framework'", err.Error())
	}
}

func TestResolveControlCrosswalk_EmptyRationaleFails(t *testing.T) {
	raw := []byte(`
version: control_crosswalk.v1
checks:
  SC.BUILDINFO.PRESENT:
    - framework: soc2
      control_id: CC7.1
      rationale: "   "
`)
	_, err := ResolveControlCrosswalk(raw, []string{"soc2"}, []string{"SC.BUILDINFO.PRESENT"}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "empty control_id or rationale") {
		t.Fatalf("expected empty control_id or rationale error, got %v", err)
	}
}

// TestResolveControlCrosswalk_JSONIncludesFilteredKey pins that the
// JSON envelope produced by ResolveControlCrosswalk emits the
// "filtered" key. The earlier shape only carried FilteredChecks on
// the in-memory CrosswalkResolution; the JSON went out without it,
// so downstream consumers parsing the file lost track of "mapping
// existed but every entry was framework-filtered" and conflated
// genuine catalog gaps with operator-noise filters.
func TestResolveControlCrosswalk_JSONIncludesFilteredKey(t *testing.T) {
	raw := []byte(`
version: control_crosswalk.v1
checks:
  SC.BUILDINFO.PRESENT:
    - framework: soc2
      control_id: CC7.1
      rationale: build metadata supports evidence
`)
	res, err := ResolveControlCrosswalk(raw, []string{"hipaa"}, []string{"SC.BUILDINFO.PRESENT"}, time.Now().UTC())
	if err != nil {
		t.Fatalf("ResolveControlCrosswalk: %v", err)
	}
	if !strings.Contains(string(res.ResolutionJSON), `"filtered"`) {
		t.Errorf("ResolutionJSON missing \"filtered\" key:\n%s", res.ResolutionJSON)
	}
	if !strings.Contains(string(res.ResolutionJSON), `"SC.BUILDINFO.PRESENT"`) {
		t.Errorf("ResolutionJSON missing the filtered check id:\n%s", res.ResolutionJSON)
	}
}

func TestParseFramework(t *testing.T) {
	tests := []struct {
		input   string
		want    Framework
		wantErr bool
	}{
		{"nist_800_53", FrameworkNIST, false},
		{"  SOC2  ", FrameworkSOC2, false},
		{"NIST-800-53", FrameworkNIST, false},
		{"PCI_DSS_v3.2.1", FrameworkPCIDSS, false},
		{"CIS-AWS-v1.4.0", FrameworkCISAWS, false},
		// iso_27001 is now an alias for the canonical iso_27001_2022 id.
		{"iso_27001", FrameworkISO27001, false},
		{"ISO 27001", FrameworkISO27001, false},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := ParseFramework(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseFramework(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseFramework(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalize_Spaces(t *testing.T) {
	cases := []struct{ in, want string }{
		{"PCI DSS v3.2.1", "pci_dss_v3.2.1"},
		{"NIST 800-53 r5", "nist_800_53_r5"},
		{"  ISO 27001  ", "iso_27001"},
		{"already_normalized", "already_normalized"},
	}
	for _, tc := range cases {
		if got := normalize(tc.in); got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
