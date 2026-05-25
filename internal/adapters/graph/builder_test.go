package graph

import (
	"slices"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/metadata"
)

func TestBuild_FindingsProduceCorrectNodes(t *testing.T) {
	t.Parallel()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:aaa",
				ControlID:       "CTL.S3.PUBLIC.001",
				ControlName:     "No Public S3 Bucket",
				AssetID:         "arn:aws:s3::123456789012:phi-records",
				AssetType:       "aws_s3_bucket",
				AssetVendor:     "aws",
				ControlSeverity: policy.SeverityCritical,
				ControlCompliance: policy.ComplianceMapping{
					"hipaa": "164.312(a)(1)",
				},
				Evidence: evaluation.Evidence{
					TemporalRisk: "Unsafe for 240h",
				},
			},
			RemediationSpec: policy.RemediationSpec{
				Action: "Enable Block Public Access",
			},
		},
	}

	g := Build(BuildInput{
		Findings:   findings,
		Now:        time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		SourcePath: "assessment.json",
	})

	// Should produce: Finding, Resource, Control, ComplianceRequirement,
	// TenantScope, RemediationAction = 6 nodes.
	if g.Metadata.NodeCount != 6 {
		t.Errorf("NodeCount = %d, want 6", g.Metadata.NodeCount)
		for _, n := range g.Nodes {
			t.Logf("  node: %s (%s)", n.ID, n.Type)
		}
	}

	// Check node types.
	wantTypes := map[NodeType]int{
		"Finding": 1, "Resource": 1, "Control": 1,
		"ComplianceRequirement": 1, "TenantScope": 1, "RemediationAction": 1,
	}
	for ntype, want := range wantTypes {
		got := g.Metadata.NodeTypes[ntype]
		if got != want {
			t.Errorf("NodeTypes[%s] = %d, want %d", ntype, got, want)
		}
	}

	// Check resource class.
	for _, n := range g.Nodes {
		if n.Type == "Resource" {
			if n.Properties["resource_class"] != "storage" {
				t.Errorf("resource_class = %v, want storage", n.Properties["resource_class"])
			}
		}
	}
}

func TestBuild_ChainsProduceCorrectNodes(t *testing.T) {
	t.Parallel()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:aaa",
				ControlID:       "CTL.S3.PUBLIC.001",
				AssetID:         "arn:aws:s3::123456789012:bucket",
				AssetType:       "aws_s3_bucket",
				AssetVendor:     "aws",
				ControlSeverity: policy.SeverityCritical,
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:bbb",
				ControlID:       "CTL.CLOUDTRAIL.ENABLED.001",
				AssetID:         "arn:aws:cloudtrail:us-east-1:123:trail/main",
				AssetType:       "aws_cloudtrail_trail",
				AssetVendor:     "aws",
				ControlSeverity: policy.SeverityHigh,
			},
		},
	}

	chains := []findingsdata.CompoundFinding{
		{
			ChainID:         "detection_blindness",
			Description:     "Multiple detection controls disabled",
			ControlsFailing: []kernel.ControlID{"CTL.S3.PUBLIC.001", "CTL.CLOUDTRAIL.ENABLED.001"},
			Severity:        policy.SeverityCritical,
			AttackStages:    []kernel.AttackStage{"initial_access", "detection_evasion"},
		},
	}

	g := Build(BuildInput{
		Findings:      findings,
		ChainFindings: chains,
		Now:           time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	})

	// Check chain-related nodes exist.
	if g.Metadata.NodeTypes["ThreatChain"] != 1 {
		t.Errorf("ThreatChain nodes = %d, want 1", g.Metadata.NodeTypes["ThreatChain"])
	}
	if g.Metadata.NodeTypes["AttackerCapability"] != 1 {
		t.Errorf("AttackerCapability nodes = %d, want 1", g.Metadata.NodeTypes["AttackerCapability"])
	}

	// Check edges.
	if g.Metadata.EdgeTypes["PRODUCES"] != 1 {
		t.Errorf("PRODUCES edges = %d, want 1", g.Metadata.EdgeTypes["PRODUCES"])
	}
	if g.Metadata.EdgeTypes["MEMBER_OF"] != 2 {
		t.Errorf("MEMBER_OF edges = %d, want 2", g.Metadata.EdgeTypes["MEMBER_OF"])
	}

	// Check kill chain phases on ThreatChain.
	for _, n := range g.Nodes {
		if n.Type == "ThreatChain" {
			phases, ok := n.Properties["kill_chain_phases"].([]map[string]string)
			if !ok || len(phases) != 2 {
				t.Errorf("kill_chain_phases = %v, want 2 phases", n.Properties["kill_chain_phases"])
			}
			attck := n.Properties["stage_span_attck"].([]string)
			if len(attck) != 2 || attck[0] != "TA0001" || attck[1] != "TA0005" {
				t.Errorf("stage_span_attck = %v, want [TA0001, TA0005]", attck)
			}
		}
	}
}

func TestBuild_EdgeDeduplication(t *testing.T) {
	t.Parallel()
	// Two findings on the same resource should produce only one BELONGS_TO_SCOPE edge.
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:aaa", ControlID: "CTL.A",
				AssetID: "arn:aws:s3::123456789012:bucket", AssetType: "aws_s3_bucket", AssetVendor: "aws",
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:bbb", ControlID: "CTL.B",
				AssetID: "arn:aws:s3::123456789012:bucket", AssetType: "aws_s3_bucket", AssetVendor: "aws",
			},
		},
	}

	g := Build(BuildInput{Findings: findings, Now: time.Now()})

	scopeEdges := 0
	for _, e := range g.Edges {
		if e.Type == "BELONGS_TO_SCOPE" {
			scopeEdges++
		}
	}
	if scopeEdges != 1 {
		t.Errorf("BELONGS_TO_SCOPE edges = %d, want 1 (deduplicated)", scopeEdges)
	}
}

func TestBuild_Empty(t *testing.T) {
	t.Parallel()
	g := Build(BuildInput{Now: time.Now()})
	if g.Metadata.NodeCount != 0 {
		t.Errorf("NodeCount = %d, want 0", g.Metadata.NodeCount)
	}
}

func TestBuild_SchemaVersion(t *testing.T) {
	t.Parallel()
	g := Build(BuildInput{Now: time.Now()})
	if g.SchemaVersion != "1" {
		t.Errorf("SchemaVersion = %q, want 1", g.SchemaVersion)
	}
	if g.OntologyVersion != metadata.OntologyVersion {
		t.Errorf("OntologyVersion = %q, want %q", g.OntologyVersion, metadata.OntologyVersion)
	}
}

// TestDeduplicateEdges_AccumulatesChainSeverities verifies that two
// edges differing only in chain_severity get merged into one edge that
// records both severities under chain_severities. Earlier shape used
// "earliest wins" and silently dropped the second value, so a finding
// belonging to chains of different severities looked like it belonged
// to only the first chain.
func TestDeduplicateEdges_AccumulatesChainSeverities(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"chain_severity": "critical"}},
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"chain_severity": "high"}},
	}
	out := deduplicateEdges(edges)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduplicated edge, got %d", len(out))
	}
	props := out[0].Properties
	if got := props["chain_severity"]; got != "critical" {
		t.Errorf("chain_severity (singular, first-wins) = %v, want critical", got)
	}
	got, ok := props["chain_severities"].([]string)
	if !ok {
		t.Fatalf("chain_severities = %T %v, want []string", props["chain_severities"], props["chain_severities"])
	}
	want := []string{"critical", "high"}
	if !slices.Equal(got, want) {
		t.Errorf("chain_severities = %v, want %v", got, want)
	}
}

func TestDeduplicateEdges_SingleChainSeverityKeepsPlural(t *testing.T) {
	t.Parallel()
	// finalizeMultiValueProps now emits the plural key regardless of
	// cardinality so consumers can reliably detect deduplication
	// occurred — distinguishing "one value seen" from "no dedup".
	edges := []Edge{
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"chain_severity": "critical"}},
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"chain_severity": "critical"}},
	}
	out := deduplicateEdges(edges)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduplicated edge, got %d", len(out))
	}
	got, present := out[0].Properties["chain_severities"]
	if !present {
		t.Fatal("chain_severities must be present after dedup, even with one distinct value")
	}
	values, ok := got.([]string)
	if !ok || len(values) != 1 || values[0] != "critical" {
		t.Errorf("chain_severities = %v (%T), want [critical]", got, got)
	}
}

// TestDeduplicateEdges_MultiValuePropertyExpansionStringSlice pins
// the per-element enumeration of slice-typed property values for
// keys registered in multiValueEdgeProps. The earlier
// `fmt.Sprint(pv)` path coerced []string{"a","b"} into the literal
// "[a b]" so consumers saw a single bracketed entry instead of two
// distinct values. Uses stage_span_attck (a real registered key)
// to drive the merge path.
func TestDeduplicateEdges_MultiValuePropertyExpansionStringSlice(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"stage_span_attck": []string{"TA0001", "TA0002"}}},
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"stage_span_attck": []string{"TA0003"}}},
	}
	out := deduplicateEdges(edges)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduplicated edge, got %d", len(out))
	}
	got, ok := out[0].Properties["stage_span_attck_all"].([]string)
	if !ok {
		t.Fatalf("stage_span_attck_all = %T %v, want []string",
			out[0].Properties["stage_span_attck_all"], out[0].Properties["stage_span_attck_all"])
	}
	want := []string{"TA0001", "TA0002", "TA0003"}
	if !slices.Equal(got, want) {
		t.Errorf("stage_span_attck_all = %v, want %v (each element stored individually, not bracketed)", got, want)
	}
}

// TestDeduplicateEdges_MultiValuePropertyExpansionAnySlice mirrors
// the []string case for the []any wire shape that survives a JSON
// unmarshal.
func TestDeduplicateEdges_MultiValuePropertyExpansionAnySlice(t *testing.T) {
	t.Parallel()
	edges := []Edge{
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"stage_span_attck": []any{"TA0001", "TA0002"}}},
		{From: "f1", To: "c1", Type: "VIOLATES", Properties: map[string]any{"stage_span_attck": []any{"TA0003"}}},
	}
	out := deduplicateEdges(edges)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduplicated edge, got %d", len(out))
	}
	got, ok := out[0].Properties["stage_span_attck_all"].([]string)
	if !ok {
		t.Fatalf("stage_span_attck_all = %T %v, want []string",
			out[0].Properties["stage_span_attck_all"], out[0].Properties["stage_span_attck_all"])
	}
	want := []string{"TA0001", "TA0002", "TA0003"}
	if !slices.Equal(got, want) {
		t.Errorf("stage_span_attck_all = %v, want %v", got, want)
	}
}
