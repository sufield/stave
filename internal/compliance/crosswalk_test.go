package compliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/securityaudit"
)

func TestResolveControlCrosswalk_Completeness(t *testing.T) {
	root := repoRootForTest(t)
	path := filepath.Join(root, "internal", "contracts", "security", "control_crosswalk.v1.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read crosswalk file: %v", err)
	}
	checkIDs := securityaudit.AllCheckIDs()

	resolved, err := ResolveControlCrosswalk(raw, []string{
		"nist_800_53",
		"cis_aws_v1.4.0",
		"soc2",
		"pci_dss_v3.2.1",
	}, checkIDs, time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ResolveControlCrosswalk() error = %v", err)
	}
	if len(resolved.MissingChecks) > 0 {
		t.Fatalf("crosswalk missing check mappings: %v", resolved.MissingChecks)
	}
	for _, checkID := range checkIDs {
		if len(resolved.ByCheck[checkID]) == 0 {
			t.Fatalf("check %s resolved to zero control refs", checkID)
		}
	}
	if !strings.Contains(string(resolved.ResolutionJSON), `"schema_version": "control-crosswalk-resolution.v1"`) {
		t.Fatalf("resolution payload missing schema_version: %s", string(resolved.ResolutionJSON))
	}
}

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
	if err == nil || !strings.Contains(err.Error(), "empty control_id/rationale") {
		t.Fatalf("expected empty control_id/rationale error, got %v", err)
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

func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found while resolving repo root")
		}
		dir = parent
	}
}
