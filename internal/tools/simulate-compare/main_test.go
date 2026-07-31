package main

import (
	"os"
	"strings"
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
		if r.AWSDecision != "" {
			t.Errorf("skip-aws mode should not have AWS decision, got %q for %s/%s",
				r.AWSDecision, r.CaseName, r.Action)
		}
	}
}

func TestAdminWildcardAllowed(t *testing.T) {
	cases := []TestCase{adminWildcard()}
	results := run(cases, true)

	for _, r := range results {
		if !r.StaveAllows {
			t.Errorf("admin wildcard: expected %s to be allowed", r.Action)
		}
	}
}

func TestS3FullAccessDeniesIAM(t *testing.T) {
	cases := []TestCase{singleServiceFullAccess()}
	results := run(cases, true)

	for _, r := range results {
		switch r.Action {
		case "s3:GetObject", "s3:PutObject", "s3:DeleteBucket":
			if !r.StaveAllows {
				t.Errorf("s3-full-access: expected %s to be allowed", r.Action)
			}
		case "iam:PutUserPolicy", "lambda:CreateFunction":
			if r.StaveAllows {
				t.Errorf("s3-full-access: expected %s to be denied", r.Action)
			}
		}
	}
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	cases := []TestCase{multiStatementDenyOverride()}
	results := run(cases, true)

	for _, r := range results {
		switch r.Action {
		case "iam:PutUserPolicy", "iam:AttachUserPolicy":
			if !r.StaveAllows {
				t.Errorf("deny-override: expected %s to survive (not denied)", r.Action)
			}
		case "iam:PassRole":
			if r.StaveAllows {
				t.Errorf("deny-override: expected %s to be explicitly denied", r.Action)
			}
		}
	}
}

func TestBoundaryConstrains(t *testing.T) {
	cases := []TestCase{boundaryConstrainsElevated()}
	results := run(cases, true)

	for _, r := range results {
		switch r.Action {
		case "s3:GetObject", "iam:PassRole":
			if !r.StaveAllows {
				t.Errorf("boundary: expected %s to pass through boundary", r.Action)
			}
		case "iam:PutUserPolicy", "iam:AttachUserPolicy":
			if r.StaveAllows {
				t.Errorf("boundary: expected %s to be blocked by boundary", r.Action)
			}
		}
	}
}

func TestFixtureExtraction(t *testing.T) {
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

	// attacker-blind should only have iam:CreateLoginProfile allowed
	for _, r := range results {
		if strings.Contains(r.CaseName, "attacker-blind") {
			switch r.Action {
			case "iam:CreateLoginProfile":
				if !r.StaveAllows {
					t.Error("attacker-blind: expected CreateLoginProfile to be allowed")
				}
			case "iam:DeleteAccountAlias", "ec2:TerminateInstances", "lambda:DeleteFunction":
				if r.StaveAllows {
					t.Errorf("attacker-blind: expected %s to be denied", r.Action)
				}
			}
		}
	}
}

func TestConditionalAllowPresent(t *testing.T) {
	cases := []TestCase{conditionalAllow()}
	results := run(cases, true)

	for _, r := range results {
		if !r.StaveAllows {
			t.Errorf("conditional: expected %s to be present (condition COULD be met)", r.Action)
		}
	}
}
