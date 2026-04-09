//go:build integration && syft

package evidence

import (
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"testing"
	"time"
)

// TestSBOM_CrossCheckSyft compares Stave's CycloneDX output against Syft.
//
// This test requires Syft to be installed:
//
//	go install github.com/anchore/syft/cmd/syft@latest
//
// Run with:
//
//	go test -tags 'integration syft' -run TestSBOM_CrossCheckSyft ./internal/app/securityaudit/evidence/
//
// It does NOT expect byte-for-byte equality. It compares semantic overlap:
// component names that appear in both tools' output.
func TestSBOM_CrossCheckSyft(t *testing.T) {
	if _, err := exec.LookPath("syft"); err != nil {
		t.Skip("syft not installed — install with: go install github.com/anchore/syft/cmd/syft@latest")
	}

	// Generate Stave's SBOM from the running binary's build info.
	provider := DefaultBuildInfoProvider{}
	buildInfo, err := provider.Collect(time.Now())
	if err != nil {
		t.Fatalf("collect build info: %v", err)
	}
	if !buildInfo.Available {
		t.Skip("build info not available in test binary")
	}

	gen := DefaultSBOMGenerator{}
	staveSnap, err := gen.Generate(buildInfo, SBOMFormatCycloneDX, time.Now())
	if err != nil {
		t.Fatalf("generate Stave SBOM: %v", err)
	}

	// Generate Syft's SBOM from the project directory.
	syftOut, err := exec.Command("syft", "dir:.", "-o", "cyclonedx-json", "-q").Output()
	if err != nil {
		t.Fatalf("run syft: %v", err)
	}

	// Parse both outputs.
	staveComponents := extractCycloneDXNames(t, staveSnap.RawJSON)
	syftComponents := extractCycloneDXNames(t, syftOut)

	if len(staveComponents) == 0 {
		t.Fatal("Stave produced zero components")
	}
	if len(syftComponents) == 0 {
		t.Fatal("Syft produced zero components")
	}

	// Check overlap: every Stave component should appear in Syft.
	var missing []string
	syftSet := make(map[string]bool, len(syftComponents))
	for _, name := range syftComponents {
		syftSet[name] = true
	}
	for _, name := range staveComponents {
		if !syftSet[name] {
			missing = append(missing, name)
		}
	}

	overlapPct := float64(len(staveComponents)-len(missing)) / float64(len(staveComponents)) * 100

	t.Logf("Stave components: %d", len(staveComponents))
	t.Logf("Syft components:  %d", len(syftComponents))
	t.Logf("Overlap:          %.0f%%", overlapPct)

	if len(missing) > 0 {
		t.Logf("Components in Stave but not Syft: %v", missing)
	}

	// Expect at least 50% overlap. Stave reads build info (Go modules only);
	// Syft scans the directory tree and may find more or different components.
	if overlapPct < 50 {
		t.Errorf("component overlap %.0f%% is below 50%% threshold", overlapPct)
	}
}

func extractCycloneDXNames(t *testing.T, raw []byte) []string {
	t.Helper()

	// Write to temp file for debugging if needed.
	tmp, _ := os.CreateTemp("", "sbom-*.json")
	if tmp != nil {
		tmp.Write(raw)
		tmp.Close()
		defer os.Remove(tmp.Name())
	}

	var doc struct {
		Components []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal CycloneDX: %v", err)
	}

	names := make([]string, len(doc.Components))
	for i, c := range doc.Components {
		names[i] = c.Name
	}
	sort.Strings(names)
	return names
}
