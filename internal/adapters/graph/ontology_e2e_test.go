package graph_test

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sufield/stave/internal/platform/metadata"
)

// buildStaveBinary builds the stave CLI and returns its path.
func buildStaveBinary(t *testing.T) (bin, repoRoot string) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile is internal/adapters/graph/ontology_e2e_test.go;
	// three levels up reaches the repo root.
	repoRoot = filepath.Join(filepath.Dir(thisFile), "..", "..", "..")

	bin = filepath.Join(t.TempDir(), "stave-ontology-test")
	build := exec.Command("go", "build", "-o", bin, "./cmd/stave")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin, repoRoot
}

// runGraphExport runs stave graph export on an assessment file and
// returns the parsed JSON graph.
func runGraphExport(t *testing.T, bin, repoRoot, assessmentPath string) map[string]any {
	t.Helper()
	cmd := exec.Command(bin, "graph", "export", "--output", assessmentPath, "--format", "json")
	cmd.Dir = repoRoot
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("graph export failed (exit %d):\n%s", ee.ExitCode(), ee.Stderr)
		}
		t.Fatalf("graph export failed: %v", err)
	}
	var g map[string]any
	if err := json.Unmarshal(stdout, &g); err != nil {
		t.Fatalf("invalid graph JSON: %v\nraw: %s", err, stdout[:min(len(stdout), 500)])
	}
	return g
}

func getNodes(g map[string]any) []map[string]any {
	raw, ok := g["nodes"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func getEdges(g map[string]any) []map[string]any {
	raw, ok := g["edges"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func filterNodesByType(nodes []map[string]any, nodeType string) []map[string]any {
	var out []map[string]any
	for _, n := range nodes {
		if n["type"] == nodeType {
			out = append(out, n)
		}
	}
	return out
}

func filterEdgesByType(edges []map[string]any, edgeType string) []map[string]any {
	var out []map[string]any
	for _, e := range edges {
		if e["type"] == edgeType {
			out = append(out, e)
		}
	}
	return out
}

func nodeProps(n map[string]any) map[string]any {
	if p, ok := n["properties"].(map[string]any); ok {
		return p
	}
	return nil
}

func getMeta(t *testing.T, g map[string]any) map[string]any {
	t.Helper()
	m, ok := g["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata missing or wrong type")
	}
	return m
}

func metaInt(m map[string]any, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return -1
}

// ---------------------------------------------------------------------------
// Experiment 1: Minimal single finding
// ---------------------------------------------------------------------------

func TestExperiment01_MinimalFinding(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	bin, repoRoot := buildStaveBinary(t)
	assessment := filepath.Join(repoRoot, "testdata", "e2e",
		"graph-ontology", "experiment-01-minimal", "assessment.json")
	if _, err := os.Stat(assessment); err != nil {
		t.Skipf("fixture not found: %s", assessment)
	}

	g := runGraphExport(t, bin, repoRoot, assessment)

	// Schema fields.
	if g["schema_version"] != "1" {
		t.Errorf("schema_version = %v, want 1", g["schema_version"])
	}
	if g["ontology_version"] != metadata.OntologyVersion {
		t.Errorf("ontology_version = %v, want %q", g["ontology_version"], metadata.OntologyVersion)
	}

	nodes := getNodes(g)
	edges := getEdges(g)
	meta := getMeta(t, g)

	// 1 Finding + 1 Resource + 1 Control + 1 ComplianceRequirement + 1 TenantScope + 1 RemediationAction = 6 nodes.
	// But exact count depends on builder internals. Assert minimum.
	if metaInt(meta, "node_count") < 3 {
		t.Errorf("node_count = %d, want >= 3", metaInt(meta, "node_count"))
	}
	if metaInt(meta, "edge_count") < 2 {
		t.Errorf("edge_count = %d, want >= 2", metaInt(meta, "edge_count"))
	}

	// Assert Finding node exists with correct properties.
	findings := filterNodesByType(nodes, "Finding")
	if len(findings) != 1 {
		t.Fatalf("Finding node count = %d, want 1", len(findings))
	}
	fp := nodeProps(findings[0])
	if fp["control_id"] != "CTL.S3.ACCEL.001" {
		t.Errorf("finding control_id = %v", fp["control_id"])
	}
	if fp["verdict"] != "fail" {
		t.Errorf("finding verdict = %v, want fail", fp["verdict"])
	}
	if fp["severity"] != "low" {
		t.Errorf("finding severity = %v, want low", fp["severity"])
	}

	// Assert Resource node.
	resources := filterNodesByType(nodes, "Resource")
	if len(resources) != 1 {
		t.Fatalf("Resource node count = %d, want 1", len(resources))
	}
	rp := nodeProps(resources[0])
	if rp["resource_class"] != "storage" {
		t.Errorf("resource_class = %v, want storage", rp["resource_class"])
	}
	if rp["provider"] != "aws" {
		t.Errorf("provider = %v, want aws", rp["provider"])
	}

	// Assert TenantScope node.
	scopes := filterNodesByType(nodes, "TenantScope")
	if len(scopes) == 0 {
		t.Error("no TenantScope node found")
	}

	// Assert TARGETS edge: Finding → Resource.
	targetsEdges := filterEdgesByType(edges, "TARGETS")
	if len(targetsEdges) != 1 {
		t.Errorf("TARGETS edge count = %d, want 1", len(targetsEdges))
	}

	// Assert no chain nodes (no chains in this assessment).
	chains := filterNodesByType(nodes, "ThreatChain")
	if len(chains) != 0 {
		t.Errorf("ThreatChain nodes = %d, want 0", len(chains))
	}

	// Metadata consistency.
	if metaInt(meta, "node_count") != len(nodes) {
		t.Errorf("metadata node_count %d != actual nodes %d",
			metaInt(meta, "node_count"), len(nodes))
	}
	if metaInt(meta, "edge_count") != len(edges) {
		t.Errorf("metadata edge_count %d != actual edges %d",
			metaInt(meta, "edge_count"), len(edges))
	}
}

// ---------------------------------------------------------------------------
// Experiment 2: Active threat chain
// ---------------------------------------------------------------------------

func TestExperiment02_ActiveChain(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	bin, repoRoot := buildStaveBinary(t)
	assessment := filepath.Join(repoRoot, "testdata", "e2e",
		"graph-ontology", "experiment-02-active-chain", "assessment.json")
	if _, err := os.Stat(assessment); err != nil {
		t.Skipf("fixture not found: %s", assessment)
	}

	g := runGraphExport(t, bin, repoRoot, assessment)

	nodes := getNodes(g)
	edges := getEdges(g)

	// Assert ThreatChain node exists and is active.
	chains := filterNodesByType(nodes, "ThreatChain")
	if len(chains) != 1 {
		t.Fatalf("ThreatChain count = %d, want 1", len(chains))
	}
	cp := nodeProps(chains[0])
	if cp["active"] != true {
		t.Errorf("ThreatChain active = %v, want true", cp["active"])
	}
	if cp["chain_id"] != "data_exfiltration_path" {
		t.Errorf("chain_id = %v, want data_exfiltration_path", cp["chain_id"])
	}
	if cp["compound_severity"] != "critical" {
		t.Errorf("compound_severity = %v, want critical", cp["compound_severity"])
	}

	// Assert kill_chain_phases in STIX 2.1 format.
	phases, ok := cp["kill_chain_phases"].([]any)
	if !ok || len(phases) == 0 {
		t.Fatal("kill_chain_phases missing or empty")
	}
	for _, phase := range phases {
		p, pOK := phase.(map[string]any)
		if !pOK {
			t.Fatal("kill_chain_phase is not a map")
		}
		if p["kill_chain_name"] != "mitre-attack" {
			t.Errorf("kill_chain_name = %v, want mitre-attack", p["kill_chain_name"])
		}
		if p["phase_name"] == nil || p["phase_name"] == "" {
			t.Error("phase_name is empty")
		}
	}

	// Assert ATT&CK tactic IDs in stage_span_attck.
	attckStages, ok := cp["stage_span_attck"].([]any)
	if !ok || len(attckStages) == 0 {
		t.Fatal("stage_span_attck missing or empty")
	}
	for _, s := range attckStages {
		str, ok := s.(string)
		if !ok || len(str) < 4 || str[:2] != "TA" {
			t.Errorf("expected ATT&CK tactic ID starting with TA, got %v", s)
		}
	}

	// Assert AttackerCapability node exists.
	capabilities := filterNodesByType(nodes, "AttackerCapability")
	if len(capabilities) != 1 {
		t.Errorf("AttackerCapability count = %d, want 1", len(capabilities))
	}

	// Assert all 3 findings are present.
	findings := filterNodesByType(nodes, "Finding")
	if len(findings) != 3 {
		t.Fatalf("Finding count = %d, want 3", len(findings))
	}

	// Assert MEMBER_OF edges: Finding → ThreatChain.
	memberEdges := filterEdgesByType(edges, "MEMBER_OF")
	if len(memberEdges) != 3 {
		t.Errorf("MEMBER_OF edge count = %d, want 3", len(memberEdges))
	}

	// Assert PRODUCES edge: ThreatChain → AttackerCapability.
	producesEdges := filterEdgesByType(edges, "PRODUCES")
	if len(producesEdges) != 1 {
		t.Errorf("PRODUCES edge count = %d, want 1", len(producesEdges))
	}

	// Assert resources span different classes.
	resources := filterNodesByType(nodes, "Resource")
	classes := make(map[string]struct{})
	for _, r := range resources {
		if rc, ok := nodeProps(r)["resource_class"].(string); ok {
			classes[rc] = struct{}{}
		}
	}
	if len(classes) < 2 {
		t.Errorf("resource classes = %d, want >= 2 (got: %v)", len(classes), classes)
	}

	// Assert no duplicate edges.
	edgeSigs := make(map[string]struct{})
	for _, e := range edges {
		sig := e["from"].(string) + "|" + e["type"].(string) + "|" + e["to"].(string)
		if _, ok := edgeSigs[sig]; ok {
			t.Errorf("duplicate edge: %s", sig)
		}
		edgeSigs[sig] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// Experiment 4: Ten findings, no chain
// ---------------------------------------------------------------------------

func TestExperiment04_NoChain(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	bin, repoRoot := buildStaveBinary(t)
	assessment := filepath.Join(repoRoot, "testdata", "e2e",
		"graph-ontology", "experiment-04-no-chain", "assessment.json")
	if _, err := os.Stat(assessment); err != nil {
		t.Skipf("fixture not found: %s", assessment)
	}

	g := runGraphExport(t, bin, repoRoot, assessment)

	nodes := getNodes(g)
	edges := getEdges(g)

	// Assert no ThreatChain or AttackerCapability nodes.
	chains := filterNodesByType(nodes, "ThreatChain")
	if len(chains) != 0 {
		t.Errorf("ThreatChain count = %d, want 0", len(chains))
	}
	caps := filterNodesByType(nodes, "AttackerCapability")
	if len(caps) != 0 {
		t.Errorf("AttackerCapability count = %d, want 0", len(caps))
	}

	// Assert no MEMBER_OF edges.
	memberEdges := filterEdgesByType(edges, "MEMBER_OF")
	if len(memberEdges) != 0 {
		t.Errorf("MEMBER_OF edge count = %d, want 0", len(memberEdges))
	}

	// Assert 10 findings.
	findings := filterNodesByType(nodes, "Finding")
	if len(findings) != 10 {
		t.Errorf("Finding count = %d, want 10", len(findings))
	}

	// Assert 10 resources (each finding targets a different resource).
	resources := filterNodesByType(nodes, "Resource")
	if len(resources) != 10 {
		t.Errorf("Resource count = %d, want 10", len(resources))
	}

	// Assert resource class diversity.
	classes := make(map[string]struct{})
	for _, r := range resources {
		if rc, ok := nodeProps(r)["resource_class"].(string); ok {
			classes[rc] = struct{}{}
		}
	}
	for _, wantClass := range []string{"storage", "database", "compute", "network", "identity"} {
		if _, ok := classes[wantClass]; !ok {
			t.Errorf("missing resource class: %s (have: %v)", wantClass, classes)
		}
	}

	// Assert 10 TARGETS edges (one per finding).
	targetsEdges := filterEdgesByType(edges, "TARGETS")
	if len(targetsEdges) != 10 {
		t.Errorf("TARGETS edge count = %d, want 10", len(targetsEdges))
	}

	// All resources should belong to same tenant scope (account 111111111111).
	scopeEdges := filterEdgesByType(edges, "BELONGS_TO_SCOPE")
	if len(scopeEdges) < 10 {
		t.Errorf("BELONGS_TO_SCOPE edge count = %d, want >= 10", len(scopeEdges))
	}

	scopes := filterNodesByType(nodes, "TenantScope")
	if len(scopes) != 1 {
		t.Errorf("TenantScope count = %d, want 1", len(scopes))
	}
	if len(scopes) > 0 {
		sp := nodeProps(scopes[0])
		if sp["account_id"] != "111111111111" {
			t.Errorf("account_id = %v, want 111111111111", sp["account_id"])
		}
	}
}

// ---------------------------------------------------------------------------
// Experiment 9: Chains removal verification
// ---------------------------------------------------------------------------

func TestExperiment09_ChainsRemoval(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	bin, repoRoot := buildStaveBinary(t)

	// stave graph --help should NOT list "chains" as a subcommand.
	cmd := exec.Command(bin, "graph", "--help")
	cmd.Dir = repoRoot
	out, _ := cmd.CombinedOutput()
	helpText := string(out)
	if containsSubcommand(helpText, "chains") {
		t.Errorf("stave graph --help should not list 'chains':\n%s", helpText)
	}

	// stave graph export should still be listed.
	if !contains(helpText, "export") {
		t.Error("stave graph --help should list 'export'")
	}

	// stave graph coverage should still be listed.
	if !contains(helpText, "coverage") {
		t.Error("stave graph --help should list 'coverage'")
	}

	// stave graph export --help should succeed.
	helpCmd := exec.Command(bin, "graph", "export", "--help")
	helpCmd.Dir = repoRoot
	if helpOut, helpErr := helpCmd.CombinedOutput(); helpErr != nil {
		t.Errorf("stave graph export --help failed: %v\n%s", helpErr, helpOut)
	}
}

// ---------------------------------------------------------------------------
// Experiment 3: STIX 2.1 export format
// ---------------------------------------------------------------------------

func TestExperiment03_STIXExport(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping: builds CLI binary")
	}

	bin, repoRoot := buildStaveBinary(t)
	assessment := filepath.Join(repoRoot, "testdata", "e2e",
		"graph-ontology", "experiment-02-active-chain", "assessment.json")
	if _, err := os.Stat(assessment); err != nil {
		t.Skipf("fixture not found: %s", assessment)
	}

	// Run stave graph export --format stix.
	cmd := exec.Command(bin, "graph", "export",
		"--output", assessment, "--format", "stix")
	cmd.Dir = repoRoot
	stdout, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("stix export failed (exit %d):\n%s", ee.ExitCode(), ee.Stderr)
		}
		t.Fatalf("stix export failed: %v", err)
	}

	var bundle map[string]any
	if err := json.Unmarshal(stdout, &bundle); err != nil {
		t.Fatalf("invalid STIX JSON: %v", err)
	}

	// STIX 2.1 Bundle fields.
	if bundle["type"] != "bundle" {
		t.Errorf("type = %v, want bundle", bundle["type"])
	}
	id, _ := bundle["id"].(string)
	if len(id) < 10 || id[:7] != "bundle-" {
		t.Errorf("id = %v, want bundle--<uuid>", id)
	}

	objects, ok := bundle["objects"].([]any)
	if !ok || len(objects) == 0 {
		t.Fatal("objects array missing or empty")
	}

	// Verify object types include expected STIX types.
	typeSet := make(map[string]struct{})
	for _, obj := range objects {
		m, ok := obj.(map[string]any)
		if !ok {
			continue
		}
		if stype, ok := m["type"].(string); ok {
			typeSet[stype] = struct{}{}
		}
	}
	for _, want := range []string{"observed-data", "infrastructure", "attack-pattern", "relationship"} {
		if _, ok := typeSet[want]; !ok {
			t.Errorf("missing STIX object type: %s (have: %v)", want, typeSet)
		}
	}
}
