package evaluation

import (
	"slices"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

// mkFinding builds a minimal Finding with the given asset, ID, score,
// and reasoning-trace observation keys.
func mkFinding(findingID, assetIDStr string, score float64, keys ...string) Finding {
	mcs := make([]MatchedClause, len(keys))
	for i, k := range keys {
		mcs[i] = MatchedClause{ObservationKey: k, Operator: "eq"}
	}
	return Finding{
		FindingID:      findingID,
		AssetID:        asset.ID(assetIDStr),
		ExposureScore:  score,
		ReasoningTrace: mcs,
	}
}

func TestBuildIssues_EmptyInput(t *testing.T) {
	if got := BuildIssues(nil); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
}

func TestBuildIssues_TwoFindingsSharingOneKey(t *testing.T) {
	findings := []Finding{
		mkFinding("f1", "bucket-a", 100, "storage.access.has_wildcard_principal", "storage.kind"),
		mkFinding("f2", "bucket-a", 80, "storage.access.policy_is_effectively_public", "storage.kind"),
	}
	issues := BuildIssues(findings)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue (shared storage.access namespace), got %d", len(issues))
	}
	if len(issues[0].MemberFindingIDs) != 2 {
		t.Errorf("expected 2 members, got %d", len(issues[0].MemberFindingIDs))
	}
	if issues[0].HeadlineFindingID != "f1" {
		t.Errorf("expected headline f1 (higher score), got %s", issues[0].HeadlineFindingID)
	}
	if issues[0].ConsolidatedScore != 100 {
		t.Errorf("expected consolidated score 100 (max), got %v", issues[0].ConsolidatedScore)
	}
	if !slices.Contains(issues[0].SharedKeys, "storage.access") {
		t.Errorf("expected shared_keys to include parent namespace 'storage.access', got %v", issues[0].SharedKeys)
	}
}

func TestBuildIssues_SharedPlusUnrelated(t *testing.T) {
	findings := []Finding{
		mkFinding("f1", "bucket-a", 100, "storage.access.has_wildcard_principal"),
		mkFinding("f2", "bucket-a", 80, "storage.access.policy_is_effectively_public"),
		mkFinding("f3", "bucket-a", 50, "storage.encryption.at_rest_enabled"),
	}
	issues := BuildIssues(findings)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues (access pair + encryption singleton), got %d", len(issues))
	}
	// Sorted by consolidated score desc: access pair (100) first, encryption singleton (50) second.
	if len(issues[0].MemberFindingIDs) != 2 {
		t.Errorf("issue[0] should have 2 members, got %d", len(issues[0].MemberFindingIDs))
	}
	if len(issues[1].MemberFindingIDs) != 1 {
		t.Errorf("issue[1] should be singleton, got %d members", len(issues[1].MemberFindingIDs))
	}
}

func TestBuildIssues_TransitiveMerge(t *testing.T) {
	// A-B share k1, B-C share k2, A-C don't directly share — union-find
	// puts all three in one cluster.
	findings := []Finding{
		mkFinding("fA", "bucket-x", 50, "storage.access.a1", "storage.access.b1"),
		mkFinding("fB", "bucket-x", 60, "storage.access.b1", "storage.controls.c1"),
		mkFinding("fC", "bucket-x", 70, "storage.controls.c1", "storage.logging.d1"),
	}
	issues := BuildIssues(findings)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue via transitive merge, got %d", len(issues))
	}
	if len(issues[0].MemberFindingIDs) != 3 {
		t.Errorf("expected 3 members, got %d", len(issues[0].MemberFindingIDs))
	}
	if issues[0].HeadlineFindingID != "fC" {
		t.Errorf("expected headline fC (highest score), got %s", issues[0].HeadlineFindingID)
	}
}

func TestBuildIssues_PerAssetScoping(t *testing.T) {
	findings := []Finding{
		mkFinding("f1", "bucket-a", 100, "storage.access.has_wildcard_principal"),
		mkFinding("f2", "bucket-b", 100, "storage.access.has_wildcard_principal"),
	}
	issues := BuildIssues(findings)
	if len(issues) != 2 {
		t.Fatalf("expected 2 issues (per-asset), got %d", len(issues))
	}
	if issues[0].AssetID == issues[1].AssetID {
		t.Errorf("issues should have different asset IDs")
	}
}

func TestBuildIssues_EmptyReasoningTrace(t *testing.T) {
	findings := []Finding{
		mkFinding("f1", "bucket-a", 100), // empty trace
		mkFinding("f2", "bucket-a", 50),  // empty trace
	}
	issues := BuildIssues(findings)
	if len(issues) != 2 {
		t.Fatalf("expected 2 singleton issues for empty-trace findings, got %d", len(issues))
	}
	for _, iss := range issues {
		if len(iss.MemberFindingIDs) != 1 {
			t.Errorf("empty-trace finding should be singleton, got %d members", len(iss.MemberFindingIDs))
		}
	}
}

func TestBuildIssues_DiscriminatorExclusion(t *testing.T) {
	// Two findings share ONLY storage.kind (a discriminator) — must
	// NOT merge, otherwise every co-asset finding collapses.
	findings := []Finding{
		mkFinding("f1", "bucket-a", 100, "storage.kind", "storage.access.a1"),
		mkFinding("f2", "bucket-a", 80, "storage.kind", "storage.encryption.e1"),
	}
	issues := BuildIssues(findings)
	if len(issues) != 2 {
		t.Fatalf("expected 2 singleton issues (storage.kind excluded from dedup), got %d", len(issues))
	}
}

func TestBuildIssues_IssueIDStability(t *testing.T) {
	findings := []Finding{
		mkFinding("f1", "bucket-a", 100, "storage.access.a1", "storage.access.b1"),
		mkFinding("f2", "bucket-a", 80, "storage.access.a1"),
	}
	a := BuildIssues(findings)
	b := BuildIssues(findings)
	if a[0].IssueID != b[0].IssueID {
		t.Errorf("IssueID not stable: %q vs %q", a[0].IssueID, b[0].IssueID)
	}
}
