package stave_test

import (
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestExportGraph_NilAssessmentReturnsNil(t *testing.T) {
	t.Parallel()
	if got := stave.ExportGraph(nil); got != nil {
		t.Errorf("ExportGraph(nil) = %+v, want nil", got)
	}
}

func TestExportGraph_FindingsProjectToNodesAndEdges(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{
			{
				FindingID:     "fid-1",
				ControlID:     "CTL.S3.ACCESS.001",
				AssetID:       "arn:aws:s3:::data-bucket",
				AssetType:     "aws_s3_bucket",
				Severity:      "high",
				ExposureScore: 7.5,
			},
			{
				FindingID:     "fid-2",
				ControlID:     "CTL.S3.ACCESS.004",
				AssetID:       "arn:aws:s3:::data-bucket",
				AssetType:     "aws_s3_bucket",
				Severity:      "high",
				ExposureScore: 8.0,
			},
		},
	}

	g := stave.ExportGraph(a)

	if len(g.Findings) != 2 {
		t.Fatalf("Findings = %d, want 2", len(g.Findings))
	}
	if len(g.Assets) != 1 {
		t.Fatalf("Assets = %d, want 1 (deduped)", len(g.Assets))
	}
	if !g.Assets[0].HasFinding {
		t.Errorf("Asset.HasFinding should be true")
	}

	// Two finding_about edges, one per finding.
	finding := 0
	for _, e := range g.Edges {
		if e.Relationship == "finding_about" {
			finding++
		}
	}
	if finding != 2 {
		t.Errorf("finding_about edges = %d, want 2", finding)
	}
}

func TestExportGraph_ChainsProjectMembers(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{
			{
				FindingID: "fid-A",
				ControlID: "CTL.S3.ACCESS.001",
				AssetID:   "asset-A",
				AssetType: "aws_s3_bucket",
				ChainMembership: []stave.ChainMembershipEntry{
					{ChainID: "data_exfiltration"},
				},
			},
			{
				FindingID: "fid-B",
				ControlID: "CTL.IAM.001",
				AssetID:   "asset-B",
				AssetType: "aws_iam_role",
				ChainMembership: []stave.ChainMembershipEntry{
					{ChainID: "data_exfiltration"},
				},
			},
			{
				FindingID: "fid-C",
				ControlID: "CTL.S3.LOG.001",
				AssetID:   "asset-C",
				AssetType: "aws_s3_bucket",
				// Not a chain member — should not appear in chain.Members.
			},
		},
		ChainFindings: []stave.ChainFinding{
			{
				ChainID:         "data_exfiltration",
				Severity:        "critical",
				CompoundScore:   12.0,
				ControlsFailing: []stave.ControlID{"CTL.S3.ACCESS.001", "CTL.IAM.001"},
			},
		},
	}

	g := stave.ExportGraph(a)

	if len(g.Chains) != 1 {
		t.Fatalf("Chains = %d, want 1", len(g.Chains))
	}
	chain := g.Chains[0]
	if chain.ChainID != "data_exfiltration" {
		t.Errorf("ChainID = %q", chain.ChainID)
	}
	if len(chain.Members) != 2 {
		t.Fatalf("chain.Members = %v, want 2", chain.Members)
	}
	wantMembers := map[stave.FindingID]bool{"fid-A": true, "fid-B": true}
	for _, fid := range chain.Members {
		if !wantMembers[fid] {
			t.Errorf("unexpected member %q", fid)
		}
	}

	// chain_member edges: one per member.
	chainMembers := 0
	for _, e := range g.Edges {
		if e.Relationship == "chain_member" {
			chainMembers++
		}
	}
	if chainMembers != 2 {
		t.Errorf("chain_member edges = %d, want 2", chainMembers)
	}

	// IsChainMember projection.
	for _, fn := range g.Findings {
		switch fn.FindingID {
		case "fid-A", "fid-B":
			if !fn.IsChainMember {
				t.Errorf("FindingNode %s should be chain member", fn.FindingID)
			}
		case "fid-C":
			if fn.IsChainMember {
				t.Errorf("FindingNode %s should not be chain member", fn.FindingID)
			}
		}
	}
}

func TestExportGraph_EdgesAreSortedDeterministically(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{
			{FindingID: "fid-Z", AssetID: "asset-Z", AssetType: "aws_s3_bucket"},
			{FindingID: "fid-A", AssetID: "asset-A", AssetType: "aws_s3_bucket"},
		},
	}
	g1 := stave.ExportGraph(a)
	g2 := stave.ExportGraph(a)
	if len(g1.Edges) != len(g2.Edges) {
		t.Fatalf("len mismatch")
	}
	for i := range g1.Edges {
		if g1.Edges[i] != g2.Edges[i] {
			t.Errorf("edge[%d] differs across runs: %+v vs %+v", i, g1.Edges[i], g2.Edges[i])
		}
	}
	// Ascending order on (Relationship, From, To).
	for i := 1; i < len(g1.Edges); i++ {
		prev, cur := g1.Edges[i-1], g1.Edges[i]
		if prev.Relationship > cur.Relationship {
			t.Errorf("relationship out of order: %q > %q", prev.Relationship, cur.Relationship)
		}
	}
}
