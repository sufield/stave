package main

import (
	"os"
	"testing"
)

func TestAllTestCasesParse(t *testing.T) {
	cases := buildTestCases()
	if len(cases) == 0 {
		t.Fatal("no test cases")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.PolicyJSON == "" {
				t.Fatal("empty policy JSON")
			}
			if len(tc.Actions) == 0 {
				t.Fatal("no actions to test")
			}
		})
	}
}

func TestResolverOnlyMode(t *testing.T) {
	cases := buildTestCases()
	results := run(cases, true)

	if len(results) == 0 {
		t.Fatal("no results")
	}
	for _, r := range results {
		if r.AWSResult != "" {
			t.Errorf("skip-aws mode should not have AWS result, got %q for %s/%s",
				r.AWSResult, r.CaseName, r.Action)
		}
	}
}

func TestAdminAllEscalation(t *testing.T) {
	cases := []TestCase{buildTestCases()[0]} // admin-all-escalation
	results := run(cases, true)

	for _, r := range results {
		if !r.StavePresent {
			t.Errorf("admin wildcard: expected %s to be present", r.Action)
		}
	}
}

func TestS3OnlyNoEscalation(t *testing.T) {
	cases := []TestCase{buildTestCases()[1]} // s3-only-no-escalation
	results := run(cases, true)

	for _, r := range results {
		if r.StavePresent {
			t.Errorf("s3-only: expected escalation action %s to be absent", r.Action)
		}
	}
}

func TestPassRoleOnly(t *testing.T) {
	cases := []TestCase{buildTestCases()[2]} // passrole-only
	results := run(cases, true)

	for _, r := range results {
		switch r.Action {
		case "iam:PassRole":
			if !r.StavePresent {
				t.Error("passrole-only: expected iam:PassRole to be present")
			}
		case "iam:PutUserPolicy", "iam:AttachUserPolicy":
			if r.StavePresent {
				t.Errorf("passrole-only: expected %s to be absent", r.Action)
			}
		}
	}
}

func TestExplicitDenyPassRole(t *testing.T) {
	cases := []TestCase{buildTestCases()[6]} // explicit-deny-passrole
	results := run(cases, true)

	for _, r := range results {
		switch r.Action {
		case "iam:PassRole":
			if r.StavePresent {
				t.Error("explicit-deny: expected iam:PassRole to be denied")
			}
		case "iam:PutUserPolicy", "iam:AttachUserPolicy":
			if !r.StavePresent {
				t.Errorf("explicit-deny: expected %s to survive (not denied)", r.Action)
			}
		}
	}
}

func TestBoundaryBlocksEscalation(t *testing.T) {
	cases := []TestCase{buildTestCases()[5]} // boundary-blocks-escalation
	results := run(cases, true)

	// Stave's resolver blocks the entire iam:* wildcard grant when
	// the boundary only allows iam:PassRole. It doesn't split iam:*
	// into individual actions. This is a conservative overapproximation:
	// iam:PassRole is absent because its carrier grant (iam:*) was
	// boundary-blocked. Known semantic difference vs AWS.
	for _, r := range results {
		if r.StavePresent {
			t.Errorf("boundary: expected %s to be blocked (iam:* blocked at boundary level)", r.Action)
		}
	}
}

func TestMultipleVectors(t *testing.T) {
	cases := []TestCase{buildTestCases()[7]} // multiple-escalation-vectors
	results := run(cases, true)

	expectPresent := map[string]bool{
		"iam:PassRole":           true,
		"iam:CreateAccessKey":    true,
		"iam:UpdateLoginProfile": true,
	}

	for _, r := range results {
		if expectPresent[r.Action] {
			if !r.StavePresent {
				t.Errorf("multiple-vectors: expected %s to be present", r.Action)
			}
		} else {
			if r.StavePresent {
				t.Errorf("multiple-vectors: expected %s to be absent", r.Action)
			}
		}
	}
}

func TestFixtureExtraction(t *testing.T) {
	// e2e-iam-recon-victim-selection has policies_json in identity;
	// escalation-specific fixtures use a different schema (identity.escalation).
	fixtureDir := "../../../testdata/e2e/e2e-iam-recon-victim-selection"
	if _, err := os.Stat(fixtureDir); err != nil {
		t.Skipf("fixture not found: %v", err)
	}

	cases, err := extractFromFixture(fixtureDir)
	if err != nil {
		t.Fatalf("extractFromFixture: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases extracted")
	}

	results := run(cases, true)
	for _, r := range results {
		if r.CaseName == "" {
			t.Error("empty case name")
		}
		if r.Action == "" {
			t.Error("empty action")
		}
	}
}
