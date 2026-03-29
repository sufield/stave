package profile

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/hipaa"
	"github.com/sufield/stave/internal/core/kernel"
)

func s3Bucket(id string, props map[string]any) asset.Asset {
	return asset.Asset{
		ID:         asset.ID(id),
		Type:       kernel.NewAssetType("aws_s3_bucket"),
		Vendor:     "aws",
		Properties: props,
	}
}

// fixtureSnapshot returns a snapshot with known invariant failures:
// - BPA not fully enabled (ACCESS.001 CRITICAL)
// - No encryption (CONTROLS.001.STRICT CRITICAL)
// - No deny non-TLS (CONTROLS.004 HIGH via invariant default)
// - No logging (AUDIT.001 CRITICAL)
// - ACLs not disabled (GOVERNANCE.001 HIGH)
// - No Object Lock (RETENTION.002 CRITICAL)
// - No versioning (CONTROLS.002 MEDIUM)
// - Has wildcard Allow (ACCESS.002 HIGH)
func fixtureSnapshot() asset.Snapshot {
	return asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		CapturedAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			s3Bucket("phi-bucket", map[string]any{
				"storage": map[string]any{
					"controls": map[string]any{
						"public_access_block": map[string]any{
							"block_public_acls":       false,
							"ignore_public_acls":      false,
							"block_public_policy":     false,
							"restrict_public_buckets": false,
						},
					},
					"ownership_controls": "ObjectWriter",
				},
				"policy_json": `{
					"Statement":[{
						"Effect":"Allow",
						"Action":"s3:*",
						"Principal":"*",
						"Resource":"arn:aws:s3:::phi-bucket/*"
					}]
				}`,
			}),
		},
	}
}

func allRegistries() []*hipaa.Registry {
	return []*hipaa.Registry{
		hipaa.AccessRegistry,
		hipaa.ControlsRegistry,
		hipaa.AuditRegistry,
		hipaa.GovernanceRegistry,
		hipaa.RetentionRegistry,
	}
}

func TestLoadProfile(t *testing.T) {
	t.Run("hipaa exists", func(t *testing.T) {
		p, err := LoadProfile("hipaa")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ID != "hipaa" {
			t.Errorf("ID: got %q", p.ID)
		}
	})
	t.Run("unknown profile", func(t *testing.T) {
		_, err := LoadProfile("nonexistent")
		if err == nil {
			t.Fatal("expected error for unknown profile")
		}
	})
}

func TestHIPAAProfile_Evaluate(t *testing.T) {
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("load hipaa: %v", err)
	}

	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// Overall must fail — the fixture has many violations.
	if report.Pass {
		t.Error("expected overall FAIL, got PASS")
	}
	if report.ProfileID != "hipaa" {
		t.Errorf("ProfileID: got %q", report.ProfileID)
	}

	// Check that implemented invariants produced results.
	resultIDs := make(map[string]bool)
	for _, r := range report.Results {
		resultIDs[r.ControlID] = true
	}

	// These invariants are implemented and should appear.
	for _, id := range []string{
		"CONTROLS.001.STRICT", "CONTROLS.004", "AUDIT.001", "ACCESS.001",
		"ACCESS.002", "GOVERNANCE.001", "RETENTION.002", "CONTROLS.002",
	} {
		if !resultIDs[id] {
			t.Errorf("expected result for %s", id)
		}
	}

	// Unimplemented invariants (AUDIT.002, ACCESS.003, ACCESS.009) should be skipped.
	for _, id := range []string{"AUDIT.002", "ACCESS.003", "ACCESS.009"} {
		if resultIDs[id] {
			t.Errorf("unexpected result for unimplemented %s", id)
		}
	}
}

func TestHIPAAProfile_SeverityCounts(t *testing.T) {
	p, _ := LoadProfile("hipaa")
	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// All implemented invariants should fail on the fixture.
	if report.FailCounts[hipaa.Critical] == 0 {
		t.Error("expected CRITICAL failures")
	}
	if report.FailCounts[hipaa.High] == 0 {
		t.Error("expected HIGH failures")
	}
	if report.FailCounts[hipaa.Medium] == 0 {
		t.Error("expected MEDIUM failures")
	}

	t.Logf("Fail counts: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d",
		report.FailCounts[hipaa.Critical],
		report.FailCounts[hipaa.High],
		report.FailCounts[hipaa.Medium],
		report.FailCounts[hipaa.Low])
}

func TestHIPAAProfile_ComplianceRefs(t *testing.T) {
	p, _ := LoadProfile("hipaa")
	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// Every result from the HIPAA profile should have a compliance ref.
	for _, r := range report.Results {
		if r.ComplianceRef == "" {
			t.Errorf("%s: missing ComplianceRef", r.ControlID)
		}
	}

	// Spot-check specific citations.
	refs := make(map[string]string)
	for _, r := range report.Results {
		refs[r.ControlID] = r.ComplianceRef
	}

	checks := map[string]string{
		"AUDIT.001":           "§164.312(b)",
		"CONTROLS.001.STRICT": "§164.312(a)(2)(iv)",
		"CONTROLS.004":        "§164.312(e)(2)(ii)",
		"ACCESS.001":          "§164.312(a)(1)",
		"CONTROLS.002":        "§164.312(c)(1)",
	}
	for id, want := range checks {
		if got := refs[id]; got != want {
			t.Errorf("%s ComplianceRef: got %q, want %q", id, got, want)
		}
	}
}

func TestHIPAAProfile_ResultsSortedBySeverity(t *testing.T) {
	p, _ := LoadProfile("hipaa")
	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// Failures should come before passes.
	seenPass := false
	for _, r := range report.Results {
		if r.Pass {
			seenPass = true
		} else if seenPass {
			t.Errorf("failure %s appeared after a pass — results not sorted correctly", r.ControlID)
		}
	}

	// Within failures, severity should be descending.
	lastRank := 999
	for _, r := range report.Results {
		if r.Pass {
			break
		}
		rank := r.Severity.Rank()
		if rank > lastRank {
			t.Errorf("severity %s appeared after lower severity — not sorted descending", r.Severity)
		}
		lastRank = rank
	}
}

func TestAllProfiles(t *testing.T) {
	ids := AllProfiles()
	found := false
	for _, id := range ids {
		if id == "hipaa" {
			found = true
		}
	}
	if !found {
		t.Error("hipaa not in AllProfiles()")
	}
}
