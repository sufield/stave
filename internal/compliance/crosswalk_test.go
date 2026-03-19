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
	_, err := ResolveControlCrosswalk(raw, []string{"iso_27001"}, []string{"SC.BUILDINFO.PRESENT"}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "unsupported compliance framework") {
		t.Fatalf("expected unsupported framework error, got %v", err)
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
		{"iso_27001", "", true},
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
