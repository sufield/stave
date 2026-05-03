package graph_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sufield/stave/internal/platform/metadata"
)

// TestGraphExportE2E builds the stave binary and runs
// `stave graph export --output <assessment>` against an existing
// H1 fixture, then validates the graph-json output structure.
func TestGraphExportE2E(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	// Build binary.
	bin := filepath.Join(t.TempDir(), "stave-graph-test")
	build := exec.Command("go", "build", "-o", bin, "./cmd/stave")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// Use CloudFront H1 fixture (has 9 findings, no chains).
	assessment := filepath.Join(repoRoot, "testdata", "e2e",
		"e2e-h1-cloudfront-2805173", "expected.out.json")
	if _, err := os.Stat(assessment); err != nil {
		t.Skipf("fixture not found: %s", assessment)
	}

	// Run graph export. Capture stderr separately so stdout stays
	// pure JSON for json.Unmarshal while diagnostic output remains
	// available when the binary exits non-zero (e.g., chain
	// validation failure during global init).
	cmd := exec.Command(bin, "graph", "export", "--output", assessment)
	cmd.Dir = repoRoot
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf
	stdout, err := cmd.Output()
	if err != nil {
		t.Fatalf("graph export failed: %v\nstderr:\n%s", err, stderrBuf.String())
	}

	// Parse output.
	var g map[string]any
	if err := json.Unmarshal(stdout, &g); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Schema fields.
	if g["schema_version"] != "1" {
		t.Errorf("schema_version = %v, want 1", g["schema_version"])
	}
	if g["ontology_version"] != metadata.OntologyVersion {
		t.Errorf("ontology_version = %v, want %q", g["ontology_version"], metadata.OntologyVersion)
	}

	// Metadata.
	meta, ok := g["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata missing or wrong type")
	}

	nodeCount := int(meta["node_count"].(float64))
	edgeCount := int(meta["edge_count"].(float64))

	if nodeCount < 10 {
		t.Errorf("node_count = %d, want >= 10", nodeCount)
	}
	if edgeCount < 10 {
		t.Errorf("edge_count = %d, want >= 10", edgeCount)
	}

	// Node type diversity.
	nodeTypes, ok := meta["node_types"].(map[string]any)
	if !ok {
		t.Fatal("node_types missing")
	}
	for _, want := range []string{"Finding", "Resource", "Control", "TenantScope"} {
		if _, exists := nodeTypes[want]; !exists {
			t.Errorf("missing node type: %s", want)
		}
	}

	// Edge type diversity.
	edgeTypes, ok := meta["edge_types"].(map[string]any)
	if !ok {
		t.Fatal("edge_types missing")
	}
	for _, want := range []string{"TARGETS", "BELONGS_TO_SCOPE"} {
		if _, exists := edgeTypes[want]; !exists {
			t.Errorf("missing edge type: %s", want)
		}
	}

	// Verify nodes array has correct structure.
	nodes, ok := g["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		t.Fatal("nodes array missing or empty")
	}
	first := nodes[0].(map[string]any)
	for _, field := range []string{"id", "type", "standard", "standard_type", "properties"} {
		if _, exists := first[field]; !exists {
			t.Errorf("node missing field: %s", field)
		}
	}

	// Verify edges array.
	edges, ok := g["edges"].([]any)
	if !ok || len(edges) == 0 {
		t.Fatal("edges array missing or empty")
	}
	firstEdge := edges[0].(map[string]any)
	for _, field := range []string{"from", "to", "type"} {
		if _, exists := firstEdge[field]; !exists {
			t.Errorf("edge missing field: %s", field)
		}
	}
}

// TestGraphExportChainsRemoved verifies stave graph chains is gone.
func TestGraphExportChainsRemoved(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	bin := filepath.Join(t.TempDir(), "stave-graph-test")
	build := exec.Command("go", "build", "-o", bin, "./cmd/stave")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// stave graph chains should not be listed as a subcommand.
	cmd := exec.Command(bin, "graph", "--help")
	out, _ := cmd.CombinedOutput()
	helpText := string(out)
	if contains(helpText, "chains") {
		t.Errorf("stave graph --help should not list 'chains' subcommand:\n%s", helpText)
	}
	// export should still be listed.
	if !contains(helpText, "export") {
		t.Error("stave graph --help should list 'export' subcommand")
	}
	// coverage should still be listed.
	if !contains(helpText, "coverage") {
		t.Error("stave graph --help should list 'coverage' subcommand")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
