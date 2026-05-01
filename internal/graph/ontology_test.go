package graph

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// --- Experiment 1: Minimal single finding ---

func TestExperiment01_MinimalFinding(t *testing.T) {
	t.Parallel()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:exp01aaa",
				ControlID:       "CTL.S3.PUBLIC.001",
				ControlName:     "S3 bucket must not be publicly accessible",
				AssetID:         "arn:aws:s3::111111111111:acme-prod-logs",
				AssetType:       "aws_s3_bucket",
				AssetVendor:     "aws",
				ControlSeverity: policy.SeverityCritical,
				Evidence: evaluation.Evidence{
					TemporalRisk: "S3 bucket acme-prod-logs is publicly accessible",
				},
			},
			RemediationSpec: policy.RemediationSpec{
				Action: "Enable Block Public Access",
			},
		},
	}

	g := Build(BuildInput{
		Findings:   findings,
		Now:        time.Date(2025, 11, 15, 10, 0, 0, 0, time.UTC),
		SourcePath: "assessment.json",
	})

	// Schema fields.
	if g.SchemaVersion != "1" {
		t.Errorf("schema_version = %q, want 1", g.SchemaVersion)
	}
	if g.OntologyVersion != "1.0" {
		t.Errorf("ontology_version = %q, want 1.0", g.OntologyVersion)
	}

	// Node counts: Finding + Resource + Control + TenantScope + RemediationAction = 5.
	if g.Metadata.NodeCount != 5 {
		t.Errorf("node_count = %d, want 5", g.Metadata.NodeCount)
		for _, n := range g.Nodes {
			t.Logf("  %s (%s)", n.ID, n.Type)
		}
	}

	// Finding node.
	finding := findNode(g.Nodes, "Finding")
	if finding == nil {
		t.Fatal("Finding node not found")
	}
	if finding.Standard != "ocsf" {
		t.Errorf("Finding.standard = %q, want ocsf", finding.Standard)
	}
	if finding.StandardType != "Security Finding (2001)" {
		t.Errorf("Finding.standard_type = %q, want Security Finding (2001)", finding.StandardType)
	}

	// Resource node with correct class.
	resource := findNode(g.Nodes, "Resource")
	if resource == nil {
		t.Fatal("Resource node not found")
	}
	if resource.Properties["resource_class"] != "storage" {
		t.Errorf("resource_class = %v, want storage", resource.Properties["resource_class"])
	}
	if resource.Properties["provider"] != "aws" {
		t.Errorf("provider = %v, want aws", resource.Properties["provider"])
	}

	// TenantScope node.
	scope := findNode(g.Nodes, "TenantScope")
	if scope == nil {
		t.Fatal("TenantScope node not found")
	}
	if scope.Properties["account_id"] != "111111111111" {
		t.Errorf("account_id = %v, want 111111111111", scope.Properties["account_id"])
	}

	// TARGETS edge.
	targets := filterEdges(g.Edges, "TARGETS")
	if len(targets) != 1 {
		t.Errorf("TARGETS edges = %d, want 1", len(targets))
	}

	// BELONGS_TO_SCOPE edge.
	scope_edges := filterEdges(g.Edges, "BELONGS_TO_SCOPE")
	if len(scope_edges) != 1 {
		t.Errorf("BELONGS_TO_SCOPE edges = %d, want 1", len(scope_edges))
	}

	// Metadata counts match actual.
	if g.Metadata.NodeCount != len(g.Nodes) {
		t.Errorf("metadata.node_count (%d) != len(nodes) (%d)", g.Metadata.NodeCount, len(g.Nodes))
	}
	if g.Metadata.EdgeCount != len(g.Edges) {
		t.Errorf("metadata.edge_count (%d) != len(edges) (%d)", g.Metadata.EdgeCount, len(g.Edges))
	}
}

// --- Experiment 2: Active threat chain ---

func TestExperiment02_ActiveChain(t *testing.T) {
	t.Parallel()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:exp02s3", ControlID: "CTL.S3.PUBLIC.001",
				ControlName: "S3 Public Access", AssetID: "arn:aws:s3::111111111111:acme-phi-records",
				AssetType: "aws_s3_bucket", AssetVendor: "aws", ControlSeverity: policy.SeverityCritical,
				ControlCompliance: policy.ComplianceMapping{"hipaa": "164.312(a)(1)"},
				ChainMembership: []evaluation.ChainMembershipEntry{
					{ChainID: "data_exfiltration_path", ChainSeverity: policy.SeverityCritical,
						StageSpan: []kernel.AttackStage{"initial_access", "exfiltration"}, Narrative: "PHI exfiltration path"},
				},
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:exp02kms", ControlID: "CTL.KMS.ROTATION.001",
				ControlName: "KMS Key Rotation", AssetID: "arn:aws:kms::111111111111:key/acme-phi-key",
				AssetType: "aws_kms_key", AssetVendor: "aws", ControlSeverity: policy.SeverityHigh,
				ChainMembership: []evaluation.ChainMembershipEntry{
					{ChainID: "data_exfiltration_path", ChainSeverity: policy.SeverityCritical,
						StageSpan: []kernel.AttackStage{"initial_access", "exfiltration"}, Narrative: "PHI exfiltration path"},
				},
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:exp02ct", ControlID: "CTL.CLOUDTRAIL.ENABLED.001",
				ControlName: "CloudTrail Enabled", AssetID: "arn:aws:cloudtrail:us-east-1:111111111111:trail/acme-main",
				AssetType: "aws_cloudtrail_trail", AssetVendor: "aws", ControlSeverity: policy.SeverityHigh,
				ChainMembership: []evaluation.ChainMembershipEntry{
					{ChainID: "data_exfiltration_path", ChainSeverity: policy.SeverityCritical,
						StageSpan: []kernel.AttackStage{"initial_access", "exfiltration"}, Narrative: "PHI exfiltration path"},
				},
			},
		},
	}

	chains := []risk.CompoundFinding{
		{
			ChainID: "data_exfiltration_path", Description: "PHI data exfiltration path",
			ControlsFailing: []kernel.ControlID{"CTL.S3.PUBLIC.001", "CTL.KMS.ROTATION.001", "CTL.CLOUDTRAIL.ENABLED.001"},
			Severity:        policy.SeverityCritical, AttackStages: []kernel.AttackStage{"initial_access", "exfiltration"},
		},
	}

	g := Build(BuildInput{
		Findings: findings, ChainFindings: chains,
		Now: time.Date(2025, 11, 15, 10, 0, 0, 0, time.UTC),
	})

	// ThreatChain node exists.
	chain := findNode(g.Nodes, "ThreatChain")
	if chain == nil {
		t.Fatal("ThreatChain node not found")
	}
	if chain.Standard != "stix" {
		t.Errorf("ThreatChain.standard = %q, want stix", chain.Standard)
	}
	if chain.StandardType != "Attack Pattern" {
		t.Errorf("ThreatChain.standard_type = %q, want Attack Pattern", chain.StandardType)
	}
	if chain.Properties["active"] != true {
		t.Error("ThreatChain should be active")
	}

	// kill_chain_phases in STIX 2.1 format.
	phases, ok := chain.Properties["kill_chain_phases"].([]map[string]string)
	if !ok || len(phases) == 0 {
		t.Fatal("kill_chain_phases missing or wrong type")
	}
	for _, p := range phases {
		if p["kill_chain_name"] != "mitre-attack" {
			t.Errorf("kill_chain_name = %q, want mitre-attack", p["kill_chain_name"])
		}
		if p["phase_name"] == "" {
			t.Error("phase_name is empty")
		}
	}

	// ATT&CK tactic IDs.
	attck, ok := chain.Properties["stage_span_attck"].([]string)
	if !ok || len(attck) != 2 || attck[0] != "TA0001" || attck[1] != "TA0010" {
		t.Errorf("stage_span_attck = %v, want [TA0001, TA0010]", chain.Properties["stage_span_attck"])
	}

	// All 3 findings are chain members.
	memberEdges := filterEdges(g.Edges, "MEMBER_OF")
	if len(memberEdges) != 3 {
		t.Errorf("MEMBER_OF edges = %d, want 3", len(memberEdges))
	}

	// PRODUCES edge exists.
	producesEdges := filterEdges(g.Edges, "PRODUCES")
	if len(producesEdges) != 1 {
		t.Errorf("PRODUCES edges = %d, want 1", len(producesEdges))
	}

	// AttackerCapability node.
	capNode := findNode(g.Nodes, "AttackerCapability")
	if capNode == nil {
		t.Fatal("AttackerCapability node not found")
	}
	if capNode.Standard != "stix" {
		t.Errorf("AttackerCapability.standard = %q, want stix", capNode.Standard)
	}

	// ComplianceRequirement node.
	req := findNode(g.Nodes, "ComplianceRequirement")
	if req == nil {
		t.Fatal("ComplianceRequirement node not found")
	}
	if req.Standard != "oscal" {
		t.Errorf("ComplianceRequirement.standard = %q, want oscal", req.Standard)
	}

	// VIOLATES edge.
	violates := filterEdges(g.Edges, "VIOLATES")
	if len(violates) == 0 {
		t.Error("expected at least one VIOLATES edge")
	}

	// No duplicate edges.
	seen := make(map[string]bool)
	for _, e := range g.Edges {
		key := e.From + "|" + e.To + "|" + string(e.Type)
		if seen[key] {
			t.Errorf("duplicate edge: %s -> %s (%s)", e.From, e.To, e.Type)
		}
		seen[key] = true
	}
}

// --- Experiment 3: Compliance requirement nodes ---

func TestExperiment03_ComplianceMapping(t *testing.T) {
	t.Parallel()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:exp03", ControlID: "CTL.S3.PUBLIC.001",
				AssetID: "arn:aws:s3::111111111111:bucket", AssetType: "aws_s3_bucket", AssetVendor: "aws",
				ControlSeverity: policy.SeverityCritical,
				ControlCompliance: policy.ComplianceMapping{
					"hipaa":        "164.312(a)(1)",
					"pci_dss_v4.0": "7.2.1",
					"soc2":         "CC6.1",
				},
			},
		},
	}

	g := Build(BuildInput{Findings: findings, Now: time.Now()})

	// 3 ComplianceRequirement nodes.
	reqs := filterNodes(g.Nodes, "ComplianceRequirement")
	if len(reqs) != 3 {
		t.Errorf("ComplianceRequirement nodes = %d, want 3", len(reqs))
	}

	// 3 MAPS_TO edges (control → requirement).
	mapsTo := filterEdges(g.Edges, "MAPS_TO")
	if len(mapsTo) != 3 {
		t.Errorf("MAPS_TO edges = %d, want 3", len(mapsTo))
	}

	// 3 VIOLATES edges (finding → requirement).
	violates := filterEdges(g.Edges, "VIOLATES")
	if len(violates) != 3 {
		t.Errorf("VIOLATES edges = %d, want 3", len(violates))
	}

	// Check requirement IDs.
	reqIDs := make(map[string]bool)
	for _, r := range reqs {
		reqIDs[r.ID] = true
	}
	for _, want := range []string{"hipaa:164.312(a)(1)", "pci_dss_v4.0:7.2.1", "soc2:CC6.1"} {
		if !reqIDs[want] {
			t.Errorf("missing ComplianceRequirement %q", want)
		}
	}
}

// --- Experiment 4: No chain ---

func TestExperiment04_NoChain(t *testing.T) {
	t.Parallel()
	types := []struct {
		assetType string
		assetID   string
	}{
		{"aws_s3_bucket", "arn:aws:s3::111111111111:acme-backup"},
		{"aws_rds_instance", "arn:aws:rds:us-east-1:111111111111:db/acme-legacy"},
		{"aws_lambda_function", "arn:aws:lambda:us-east-1:111111111111:function/acme-api"},
		{"aws_security_group", "arn:aws:ec2:us-east-1:111111111111:security-group/sg-0001"},
		{"aws_iam_user", "arn:aws:iam::111111111111:user/legacy-svc"},
		{"aws_kms_key", "arn:aws:kms:us-east-1:111111111111:key/acme-backup-key"},
		{"aws_cloudfront_distribution", "arn:aws:cloudfront::111111111111:distribution/E1"},
		{"aws_apigateway_stage", "arn:aws:apigateway:us-east-1:111111111111:restapis/abc"},
		{"aws_sqs_queue", "arn:aws:sqs:us-east-1:111111111111:acme-orders"},
		{"aws_rds_instance", "arn:aws:rds:us-east-1:111111111111:db/acme-reports"},
	}

	findings := make([]remediation.Finding, len(types))
	for i, tt := range types {
		findings[i] = remediation.Finding{
			Finding: evaluation.Finding{
				FindingID: kernel.FindingID("sha256:exp04" + string(rune('a'+i))),
				ControlID: kernel.ControlID("CTL.TEST." + string(rune('A'+i))),
				AssetID:   asset.ID(tt.assetID), AssetType: kernel.AssetType(tt.assetType),
				AssetVendor: "aws", ControlSeverity: policy.SeverityHigh,
			},
		}
	}

	g := Build(BuildInput{Findings: findings, Now: time.Now()})

	// No ThreatChain or AttackerCapability nodes.
	if len(filterNodes(g.Nodes, "ThreatChain")) != 0 {
		t.Error("expected 0 ThreatChain nodes")
	}
	if len(filterNodes(g.Nodes, "AttackerCapability")) != 0 {
		t.Error("expected 0 AttackerCapability nodes")
	}
	if len(filterEdges(g.Edges, "MEMBER_OF")) != 0 {
		t.Error("expected 0 MEMBER_OF edges")
	}

	// All 10 findings produce Resource nodes.
	resources := filterNodes(g.Nodes, "Resource")
	if len(resources) != 10 {
		t.Errorf("Resource nodes = %d, want 10", len(resources))
	}

	// Check resource class diversity.
	classes := make(map[string]bool)
	for _, r := range resources {
		classes[r.Properties["resource_class"].(string)] = true
	}
	for _, want := range []string{"storage", "database", "compute", "network", "identity", "key", "cdn", "queue"} {
		if !classes[want] {
			t.Errorf("missing resource_class %q", want)
		}
	}
}

// --- Experiment 9: JSON roundtrip ---

func TestExperiment09_JSONRoundTrip(t *testing.T) {
	t.Parallel()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID: "sha256:rt01", ControlID: "CTL.S3.PUBLIC.001",
				AssetID: "arn:aws:s3::111111111111:bucket", AssetType: "aws_s3_bucket", AssetVendor: "aws",
				ControlSeverity: policy.SeverityCritical,
			},
		},
	}
	g := Build(BuildInput{Findings: findings, Now: time.Date(2025, 11, 15, 0, 0, 0, 0, time.UTC)})

	// Marshal to JSON and back.
	data, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed GraphData
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if parsed.SchemaVersion != g.SchemaVersion {
		t.Errorf("schema_version roundtrip: %q != %q", parsed.SchemaVersion, g.SchemaVersion)
	}
	if parsed.Metadata.NodeCount != g.Metadata.NodeCount {
		t.Errorf("node_count roundtrip: %d != %d", parsed.Metadata.NodeCount, g.Metadata.NodeCount)
	}
	if len(parsed.Nodes) != len(g.Nodes) {
		t.Errorf("nodes roundtrip: %d != %d", len(parsed.Nodes), len(g.Nodes))
	}
	if len(parsed.Edges) != len(g.Edges) {
		t.Errorf("edges roundtrip: %d != %d", len(parsed.Edges), len(g.Edges))
	}
}

// --- Helpers ---

func findNode(nodes []Node, nodeType NodeType) *Node {
	for i := range nodes {
		if nodes[i].Type == nodeType {
			return &nodes[i]
		}
	}
	return nil
}

func filterNodes(nodes []Node, nodeType NodeType) []Node {
	var out []Node
	for _, n := range nodes {
		if n.Type == nodeType {
			out = append(out, n)
		}
	}
	return out
}

func filterEdges(edges []Edge, edgeType EdgeType) []Edge {
	var out []Edge
	for _, e := range edges {
		if e.Type == edgeType {
			out = append(out, e)
		}
	}
	return out
}
