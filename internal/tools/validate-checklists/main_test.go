package main

import (
	"strings"
	"testing"
)

func TestValidateChecklists_NegativeSelfTest(t *testing.T) {
	// Synthetic checklist with three deliberate violations:
	// 1. Duplicate ID (KMS-TEST-01 appears twice)
	// 2. Missing verdict on one check (file is verdict-bearing)
	// 3. OOS without verdict_reason
	yaml := `
standard: "Test Checklist"
checks:
  - id: KMS-TEST-01
    service: FOO
    description: "first"
    verdict: COVERED
  - id: KMS-TEST-01
    service: BAR
    description: "duplicate id"
    verdict: COVERED
  - id: KMS-TEST-02
    service: BAZ
    description: "missing verdict"
  - id: KMS-TEST-03
    service: QUX
    description: "OOS without reason"
    verdict: OOS
`
	errs := validateBytes("synthetic.yaml", []byte(yaml))

	if len(errs) == 0 {
		t.Fatal("expected violations but got none")
	}

	wantPatterns := []string{
		"duplicate id",
		"missing verdict",
		"OOS without verdict_reason",
	}
	for _, pat := range wantPatterns {
		found := false
		for _, e := range errs {
			if strings.Contains(e, pat) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected violation containing %q, got: %v", pat, errs)
		}
	}
}

func TestValidateChecklists_StructuralViolations(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "missing name",
			yaml:    "checks:\n  - id: X\n",
			wantErr: "missing name or standard",
		},
		{
			name:    "no checks",
			yaml:    "standard: test\nchecks: []\n",
			wantErr: "no checks",
		},
		{
			name:    "missing id",
			yaml:    "standard: test\nchecks:\n  - service: foo\n",
			wantErr: "missing id",
		},
		{
			name:    "total mismatch",
			yaml:    "standard: test\ntotal: 5\nchecks:\n  - id: X\n",
			wantErr: "declared total 5 but found 1",
		},
		{
			name:    "invalid verdict",
			yaml:    "standard: test\nchecks:\n  - id: X\n    verdict: BOGUS\n",
			wantErr: "invalid verdict",
		},
		{
			name:    "evidence-gated without condition",
			yaml:    "standard: test\nchecks:\n  - id: X\n    verdict: EVIDENCE-GATED\n",
			wantErr: "EVIDENCE-GATED without verdict_condition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validateBytes("test.yaml", []byte(tt.yaml))
			if len(errs) == 0 {
				t.Fatalf("expected error containing %q, got none", tt.wantErr)
			}
			found := false
			for _, e := range errs {
				if strings.Contains(e, tt.wantErr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, errs)
			}
		})
	}
}

func TestValidateChecklists_ValidNonVerdictFile(t *testing.T) {
	yaml := `
standard: "CIS Test"
checks:
  - id: CIS-1.1
    service: IAM
    description: "test check"
  - id: CIS-1.2
    service: IAM
    description: "another check"
`
	errs := validateBytes("valid.yaml", []byte(yaml))
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}

func TestValidateChecklists_ValidVerdictFile(t *testing.T) {
	yaml := `
standard: "KMS Test"
total: 3
checks:
  - id: KMS-01
    verdict: COVERED
  - id: KMS-02
    verdict: EVIDENCE-GATED
    verdict_condition: "collector adds asset type"
  - id: KMS-03
    verdict: OOS
    verdict_reason: "lifecycle: closed"
`
	errs := validateBytes("valid-verdict.yaml", []byte(yaml))
	if len(errs) > 0 {
		t.Errorf("expected no errors, got: %v", errs)
	}
}
