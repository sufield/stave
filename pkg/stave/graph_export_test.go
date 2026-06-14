package stave_test

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/sir"
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
	wantMembers := map[stave.FindingID]struct{}{"fid-A": {}, "fid-B": {}}
	for _, fid := range chain.Members {
		if _, ok := wantMembers[fid]; !ok {
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

// TestExportGraph_LifecycleHydratedFromFinding asserts that when
// the public Finding carries non-zero temporal evidence
// (FirstUnsafeAt / LastSeenUnsafeAt / UnsafeDurationHours), the
// projected FindingNode.Lifecycle reflects those values verbatim.
// This is the data path Z3 / SMT consumers reading export-graph
// rely on for dwell-time reasoning without re-walking
// observation snapshots.
func TestExportGraph_LifecycleHydratedFromFinding(t *testing.T) {
	t.Parallel()
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	last := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	a := &stave.Assessment{
		Findings: []stave.Finding{
			{
				FindingID:           "fid-temporal",
				ControlID:           "CTL.S3.ACCESS.001",
				AssetID:             "arn:aws:s3:::data-bucket",
				AssetType:           "aws_s3_bucket",
				Severity:            "high",
				ExposureScore:       7.5,
				FirstUnsafeAt:       first,
				LastSeenUnsafeAt:    last,
				UnsafeDurationHours: 168,
			},
		},
	}
	g := stave.ExportGraph(a)
	if len(g.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(g.Findings))
	}
	lc := g.Findings[0].Lifecycle
	if lc == nil {
		t.Fatal("Lifecycle should be populated when Finding carries temporal evidence")
	}
	if !lc.FirstUnsafeAt.Equal(first) {
		t.Errorf("FirstUnsafeAt = %v, want %v", lc.FirstUnsafeAt, first)
	}
	if !lc.LastSeenUnsafeAt.Equal(last) {
		t.Errorf("LastSeenUnsafeAt = %v, want %v", lc.LastSeenUnsafeAt, last)
	}
	if lc.UnsafeDurationHours != 168 {
		t.Errorf("UnsafeDurationHours = %v, want 168", lc.UnsafeDurationHours)
	}
}

// TestExportGraph_LifecycleNilWhenNoTemporalEvidence guards the
// negative case: a Finding with no lifecycle data (e.g. a single-
// snapshot evaluation) projects to a FindingNode whose Lifecycle
// pointer is nil. Consumers can safely branch on the pointer
// rather than checking three zero-valued fields individually.
func TestExportGraph_LifecycleNilWhenNoTemporalEvidence(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{
			{
				FindingID: "fid-no-time",
				ControlID: "CTL.S3.ACCESS.001",
				AssetID:   "arn:aws:s3:::data-bucket",
				AssetType: "aws_s3_bucket",
				Severity:  "high",
			},
		},
	}
	g := stave.ExportGraph(a)
	if len(g.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(g.Findings))
	}
	if g.Findings[0].Lifecycle != nil {
		t.Errorf("Lifecycle should be nil when Finding has no temporal evidence; got %+v",
			g.Findings[0].Lifecycle)
	}
}

// TestExportGraph_NoOptionsBackwardCompat confirms zero-arg
// callers see the same shape they always did — no
// TransitiveReachability, no AssetNode.Lifecycle. The variadic
// rollout from PR-7 must not regress existing consumers.
func TestExportGraph_NoOptionsBackwardCompat(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{{
			FindingID:     "fid-1",
			ControlID:     "CTL.X.001",
			AssetID:       "arn:aws:s3:::b",
			AssetType:     "aws_s3_bucket",
			Severity:      "high",
			ExposureScore: 5,
		}},
	}
	g := stave.ExportGraph(a)
	if g == nil {
		t.Fatal("nil graph")
	}
	if g.TransitiveReachability != nil {
		t.Errorf("zero-arg call must not populate TransitiveReachability, got %d entries",
			len(g.TransitiveReachability))
	}
	for i := range g.Assets {
		if g.Assets[i].Lifecycle != nil {
			t.Errorf("Assets[%d].Lifecycle should be nil without WithSIRDocument", i)
		}
	}
}

// TestExportGraph_WithSIRDocumentHydratesReachability surfaces
// transitive role chains from the SIR document into
// TransitiveReachability. Predicate-driven check: a SIR doc with
// one IdentityFact carrying a 2-hop chain produces one
// ReachabilityPath with two hops.
func TestExportGraph_WithSIRDocumentHydratesReachability(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{{
			FindingID: "fid-1",
			AssetID:   "arn:aws:iam::111:role/admin",
			AssetType: "aws_iam_role",
		}},
	}
	doc := &sir.Document{
		Identities: []sir.IdentityFact{{
			PrincipalID: "arn:aws:iam::111:user/dev",
			RoleChains: []sir.RoleChainFact{{
				Hops: []sir.RoleHopFact{
					{From: "arn:aws:iam::111:user/dev", To: "arn:aws:iam::111:role/onboarding"},
					{From: "arn:aws:iam::111:role/onboarding", To: "arn:aws:iam::111:role/admin", CrossAccount: true, HopType: "sts:AssumeRole"},
				},
				FinalRoleARN:    "arn:aws:iam::111:role/admin",
				TransitiveLevel: "admin",
			}},
		}},
	}
	g := stave.ExportGraph(a, stave.WithSIRDocument(doc))
	if got := len(g.TransitiveReachability); got != 1 {
		t.Fatalf("TransitiveReachability len = %d, want 1", got)
	}
	p := g.TransitiveReachability[0]
	if p.FromPrincipal != "arn:aws:iam::111:user/dev" {
		t.Errorf("FromPrincipal = %q", p.FromPrincipal)
	}
	if p.FinalRole != "arn:aws:iam::111:role/admin" {
		t.Errorf("FinalRole = %q", p.FinalRole)
	}
	if !p.CrossAccountHop {
		t.Errorf("CrossAccountHop should be true (any hop is cross-account)")
	}
	if got := len(p.Hops); got != 2 {
		t.Errorf("Hops len = %d, want 2", got)
	}
	if p.TransitiveLevel != "admin" {
		t.Errorf("TransitiveLevel = %q", p.TransitiveLevel)
	}
}

// TestExportGraph_WithSIRDocumentHydratesAssetLifecycle attaches
// the AssetFact.Lifecycle envelope to the matching AssetNode.
// AssetNodes whose ID has no SIR AssetFact match get nil
// lifecycle (the omitempty behaviour callers rely on).
func TestExportGraph_WithSIRDocumentHydratesAssetLifecycle(t *testing.T) {
	t.Parallel()
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	last := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)
	a := &stave.Assessment{
		Findings: []stave.Finding{{
			FindingID: "fid-1",
			AssetID:   "arn:aws:s3:::lifecycle-bucket",
			AssetType: "aws_s3_bucket",
		}},
	}
	doc := &sir.Document{
		Assets: []sir.AssetFact{{
			ID:   "arn:aws:s3:::lifecycle-bucket",
			Type: "aws_s3_bucket",
			Lifecycle: &sir.AssetLifecycleFact{
				Provisioned: true,
				FirstSeen:   first,
				LastSeen:    last,
			},
		}},
	}
	g := stave.ExportGraph(a, stave.WithSIRDocument(doc))
	if len(g.Assets) != 1 {
		t.Fatalf("Assets len = %d, want 1", len(g.Assets))
	}
	lc := g.Assets[0].Lifecycle
	if lc == nil {
		t.Fatal("Asset.Lifecycle is nil; should be populated from SIR")
	}
	if !lc.Provisioned {
		t.Errorf("Provisioned = false, want true")
	}
	if !lc.FirstSeen.Equal(first) {
		t.Errorf("FirstSeen = %v", lc.FirstSeen)
	}
	if !lc.LastSeen.Equal(last) {
		t.Errorf("LastSeen = %v", lc.LastSeen)
	}
}

// TestExportGraph_WithSIRDocumentNilDocIsNoOp confirms passing
// a nil SIR doc behaves like the zero-options call (no
// hydration, no panic). Lets callers thread the option
// unconditionally without a nil-guard.
func TestExportGraph_WithSIRDocumentNilDocIsNoOp(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{{
			FindingID: "fid-1",
			AssetID:   "arn:aws:s3:::b",
			AssetType: "aws_s3_bucket",
		}},
	}
	g := stave.ExportGraph(a, stave.WithSIRDocument(nil))
	if g == nil {
		t.Fatal("nil graph from valid assessment")
	}
	if g.TransitiveReachability != nil {
		t.Errorf("nil SIR doc populated TransitiveReachability: %+v", g.TransitiveReachability)
	}
}

// TestExportGraph_WithSIRDocumentDeterministic confirms
// (assessment, sir.Document) input produces byte-stable
// TransitiveReachability ordering across runs. Path slice is
// sorted by (FromPrincipal, FinalRole) per the WithSIRDocument
// contract.
func TestExportGraph_WithSIRDocumentDeterministic(t *testing.T) {
	t.Parallel()
	a := &stave.Assessment{
		Findings: []stave.Finding{{FindingID: "fid", AssetID: "arn:aws:s3:::b"}},
	}
	doc := &sir.Document{
		Identities: []sir.IdentityFact{
			{PrincipalID: "z-user", RoleChains: []sir.RoleChainFact{{FinalRoleARN: "z-role"}}},
			{PrincipalID: "a-user", RoleChains: []sir.RoleChainFact{
				{FinalRoleARN: "z-role"},
				{FinalRoleARN: "a-role"},
			}},
		},
	}
	first := stave.ExportGraph(a, stave.WithSIRDocument(doc))
	for run := range 5 {
		next := stave.ExportGraph(a, stave.WithSIRDocument(doc))
		if len(first.TransitiveReachability) != len(next.TransitiveReachability) {
			t.Fatalf("run %d: count differs", run)
		}
		for i := range first.TransitiveReachability {
			a, b := &first.TransitiveReachability[i], &next.TransitiveReachability[i]
			if a.FromPrincipal != b.FromPrincipal || a.FinalRole != b.FinalRole {
				t.Errorf("run %d: paths[%d] (Principal,Role) differs: %v vs %v",
					run, i, *a, *b)
			}
		}
	}
	// Sorted by (FromPrincipal, FinalRole): a-user/a-role,
	// a-user/z-role, z-user/z-role.
	want := []string{"a-user|a-role", "a-user|z-role", "z-user|z-role"}
	for i, p := range first.TransitiveReachability {
		got := p.FromPrincipal + "|" + p.FinalRole
		if got != want[i] {
			t.Errorf("paths[%d] = %q, want %q", i, got, want[i])
		}
	}
}
