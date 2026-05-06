package sirbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/sir"
)

// loadRawVectorFixture loads the L5 fixture into an asset.Snapshot.
// The fixture is intentionally minimal: one bucket with policy +
// public ACL + bucket-level PAB.BlockPublicAcls=true + no
// attached IAM.
func loadRawVectorFixture(t *testing.T) asset.Snapshot {
	t.Helper()
	path := filepath.Join("..", "..", "..", "internal", "core", "sir", "testdata", "s3_raw_vectors", "snapshot.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return snap
}

// TestBuildRawVectorGroup is the L5 positive gate: the SIR
// builder, given the fixture, produces exactly one
// ResourceFactGroup with the expected raw vectors and SourceRef
// identities.
//
// No "effective" / "suppressed" / "is_violating" fields are
// asserted — the SIR is purely structural at this layer.
func TestBuildRawVectorGroup(t *testing.T) {
	snap := loadRawVectorFixture(t)
	b := sir.NewBuilder(sir.WithResourceFactGrouper(NewAWSS3FactGrouper()))
	doc, err := b.Build(nil, []asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(doc.ResourceGroups) != 1 {
		t.Fatalf("expected 1 ResourceFactGroup, got %d", len(doc.ResourceGroups))
	}
	gr := doc.ResourceGroups[0]
	if gr.AssetID != "arn:aws:s3:::raw-vectors" {
		t.Errorf("AssetID: got %q", gr.AssetID)
	}

	// BucketPolicy: 1 statement, Allow, principal IsPublic.
	if len(gr.BucketPolicy) != 1 {
		t.Fatalf("BucketPolicy: want 1, got %d", len(gr.BucketPolicy))
	}
	stmt := gr.BucketPolicy[0]
	if stmt.Effect != "Allow" {
		t.Errorf("BucketPolicy[0].Effect: want Allow, got %q", stmt.Effect)
	}
	if len(stmt.Principals) == 0 || !stmt.Principals[0].IsPublic {
		t.Errorf("BucketPolicy[0].Principals[0] must be IsPublic=true: %+v", stmt.Principals)
	}

	// ACLGrants: 1, AllUsers READ.
	if len(gr.ACLGrants) != 1 {
		t.Fatalf("ACLGrants: want 1, got %d", len(gr.ACLGrants))
	}
	if gr.ACLGrants[0].GranteeURI != "http://acs.amazonaws.com/groups/global/AllUsers" {
		t.Errorf("ACLGrants[0].GranteeURI: got %q", gr.ACLGrants[0].GranteeURI)
	}
	if gr.ACLGrants[0].Permission != "READ" {
		t.Errorf("ACLGrants[0].Permission: got %q", gr.ACLGrants[0].Permission)
	}

	// PAB: 1 fact, BlockPublicAcls=true others false.
	if len(gr.PAB) != 1 {
		t.Fatalf("PAB: want 1, got %d", len(gr.PAB))
	}
	pab := gr.PAB[0]
	if !pab.BlockPublicAcls || pab.IgnorePublicAcls || pab.BlockPublicPolicy || pab.RestrictPublicBuckets {
		t.Errorf("PAB flags wrong: %+v", pab)
	}

	// AttachedIAM: empty (no identities in fixture).
	if len(gr.AttachedIAM) != 0 {
		t.Errorf("AttachedIAM: want 0, got %d", len(gr.AttachedIAM))
	}

	// Every fact carries a non-empty SourceRef.
	if gr.Source.IsEmpty() {
		t.Errorf("Group SourceRef empty")
	}
	if gr.BucketPolicy[0].Source.IsEmpty() {
		t.Errorf("BucketPolicy[0].Source empty")
	}
	if gr.ACLGrants[0].Source.IsEmpty() {
		t.Errorf("ACLGrants[0].Source empty")
	}
	if gr.PAB[0].Source.IsEmpty() {
		t.Errorf("PAB[0].Source empty")
	}
}

// TestSIRContainsNoDerivedFields is the L5 drift guard: walks
// every JSON field name in the marshaled SIR document and
// fails if any name matches a "derived field" pattern. Future
// drift back into Stave-side aggregation surfaces here as a
// fast, attribution-pointing failure rather than a months-
// later differential-suite divergence.
//
// Update the deny-list ONLY to add patterns when a new
// aggregation field would re-introduce the bug. Never weaken
// the test by removing patterns.
func TestSIRContainsNoDerivedFields(t *testing.T) {
	snap := loadRawVectorFixture(t)
	b := sir.NewBuilder(sir.WithResourceFactGrouper(NewAWSS3FactGrouper()))
	doc, err := b.Build(nil, []asset.Snapshot{snap}, time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Patterns target DERIVED-aggregation fields specifically.
	// Pure AWS-schema raw inputs (public_access_block,
	// block_public_acls, is_public on a TypedPrincipal) are
	// inputs, not outputs — they pass through cleanly.
	denyPatterns := []*regexp.Regexp{
		regexp.MustCompile(`"effective_[a-z_]+"`),      // effective_*
		regexp.MustCompile(`"[a-z_]+_suppressed"`),     // *_suppressed
		regexp.MustCompile(`"suppressed"`),             // bare suppressed flag
		regexp.MustCompile(`"is_violating"`),           // derived violation flag
		regexp.MustCompile(`"public_via_[a-z_]+"`),     // public_via_acl
		regexp.MustCompile(`"public_through_[a-z_]+"`), // public_through_*
		regexp.MustCompile(`"composite_[a-z_]+"`),      // composite_score, composite_principal
		regexp.MustCompile(`"effective_permissions"`),  // the retired top-level field
		regexp.MustCompile(`"contributing_sources"`),   // EFP-era field; never a Document-level concept now
	}
	body := string(encoded)
	for _, pat := range denyPatterns {
		if pat.MatchString(body) {
			t.Errorf(
				"SIR drift detected: JSON body matched derived-field pattern %s.\n"+
					"Stave is the Librarian — no aggregation fields belong in the SIR. "+
					"Move the offending logic into the Z3 solver in python/solver/.\n"+
					"Body: %s",
				pat.String(), body,
			)
		}
	}
}
