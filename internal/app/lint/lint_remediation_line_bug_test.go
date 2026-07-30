package lint

import (
	"testing"
)

func TestLint_RemediationMissingAction_ReportsRemediationLine(t *testing.T) {
	yamlData := []byte(`id: CTL.S3.PUBLIC.001
dsl_version: ctrl.v1
name: Public S3 Bucket
description: S3 bucket is public
remediation:
  description: Fix the bucket
`)

	l := NewLinter()
	diags := l.LintBytes("control.yaml", yamlData)

	var remDiag *Diagnostic
	for i := range diags {
		if diags[i].RuleID == "CTL_META_REMEDIATION_REQUIRED" {
			remDiag = &diags[i]
			break
		}
	}

	if remDiag == nil {
		t.Fatalf("expected CTL_META_REMEDIATION_REQUIRED diagnostic")
	}

	// Line should be 5 (where remediation: starts), not 1
	if remDiag.Line != 5 {
		t.Errorf("expected diagnostic line 5 for missing remediation action, got line %d", remDiag.Line)
	}
}
