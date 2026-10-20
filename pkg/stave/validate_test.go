package stave_test

import (
	"context"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestValidate_RequiresSnapshotsDir(t *testing.T) {
	_, err := stave.Validate(context.Background(), stave.ValidateConfig{})
	if err == nil {
		t.Fatal("expected error for empty SnapshotsDir")
	}
}

func TestValidate_BuiltinCatalog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	result, err := stave.Validate(context.Background(), stave.ValidateConfig{
		SnapshotsDir: "../../testdata/e2e/e2e-s3-golden-path/observations",
	})
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if result.ControlsChecked == 0 {
		t.Error("expected controls to be checked")
	}
	if result.SnapshotsChecked == 0 {
		t.Error("expected snapshots to be checked")
	}
	if !result.HasCheckedControls() {
		t.Error("HasCheckedControls() = false, want true")
	}
	if !result.HasCheckedSnapshots() {
		t.Error("HasCheckedSnapshots() = false, want true")
	}
}

func TestValidationSeverity_DomainMethods(t *testing.T) {
	errSev := stave.ValidationSeverityError
	if errSev.String() != "error" {
		t.Errorf("String() = %q, want error", errSev.String())
	}
	if !errSev.IsError() {
		t.Error("IsError() = false, want true")
	}
	if errSev.IsWarning() {
		t.Error("IsWarning() = true, want false")
	}

	warnSev := stave.ValidationSeverityWarning
	if warnSev.String() != "warning" {
		t.Errorf("String() = %q, want warning", warnSev.String())
	}
	if !warnSev.IsWarning() {
		t.Error("IsWarning() = false, want true")
	}
	if warnSev.IsError() {
		t.Error("IsError() = true, want false")
	}
}

func TestValidationFinding_DomainMethods(t *testing.T) {
	fErr := stave.ValidationFinding{
		RuleID:   "RULE-001",
		Severity: stave.ValidationSeverityError,
		Message:  "missing field",
	}
	if !fErr.IsError() || fErr.IsWarning() {
		t.Error("fErr error/warning check failed")
	}

	fWarn := stave.ValidationFinding{
		RuleID:   "RULE-002",
		Severity: stave.ValidationSeverityWarning,
		Message:  "extra field",
	}
	if !fWarn.IsWarning() || fWarn.IsError() {
		t.Error("fWarn error/warning check failed")
	}
}

func TestValidationFindings_DomainMethods(t *testing.T) {
	var empty stave.ValidationFindings
	if empty.Len() != 0 || !empty.IsEmpty() {
		t.Error("empty findings should have len 0 and be empty")
	}
	if empty.Errors() != nil || empty.Warnings() != nil || empty.ByRuleID("X") != nil || empty.RuleIDs() != nil {
		t.Error("empty findings methods should return nil")
	}

	f1 := stave.ValidationFinding{RuleID: "RULE-A", Severity: stave.ValidationSeverityError, Message: "err1"}
	f2 := stave.ValidationFinding{RuleID: "RULE-B", Severity: stave.ValidationSeverityWarning, Message: "warn1"}
	f3 := stave.ValidationFinding{RuleID: "RULE-A", Severity: stave.ValidationSeverityError, Message: "err2"}
	findings := stave.ValidationFindings{f1, f2, f3}

	if findings.Len() != 3 {
		t.Errorf("Len() = %d, want 3", findings.Len())
	}
	if findings.IsEmpty() {
		t.Error("IsEmpty() = true, want false")
	}

	errs := findings.Errors()
	if errs.Len() != 2 {
		t.Errorf("Errors().Len() = %d, want 2", errs.Len())
	}

	warns := findings.Warnings()
	if warns.Len() != 1 {
		t.Errorf("Warnings().Len() = %d, want 1", warns.Len())
	}

	ruleAFindings := findings.ByRuleID("RULE-A")
	if ruleAFindings.Len() != 2 {
		t.Errorf("ByRuleID(RULE-A).Len() = %d, want 2", ruleAFindings.Len())
	}

	ruleIDs := findings.RuleIDs()
	if len(ruleIDs) != 2 {
		t.Errorf("RuleIDs() count = %d, want 2", len(ruleIDs))
	}
}

func TestValidationResult_DomainMethods(t *testing.T) {
	clean := &stave.ValidationResult{
		Valid:            true,
		ControlsChecked:  10,
		SnapshotsChecked: 2,
	}
	if !clean.IsValid() {
		t.Error("IsValid() = false, want true")
	}
	if clean.HasErrors() || clean.HasWarnings() {
		t.Error("clean result should not have errors or warnings")
	}
	if !clean.IsClean() {
		t.Error("IsClean() = false, want true")
	}
	if clean.TotalFindings() != 0 {
		t.Errorf("TotalFindings() = %d, want 0", clean.TotalFindings())
	}
	if !clean.HasCheckedControls() || !clean.HasCheckedSnapshots() {
		t.Error("clean result should have checked controls and snapshots")
	}

	withIssues := &stave.ValidationResult{
		Valid:        false,
		ErrorCount:   2,
		WarningCount: 1,
		Findings: stave.ValidationFindings{
			{RuleID: "R1", Severity: stave.ValidationSeverityError},
			{RuleID: "R2", Severity: stave.ValidationSeverityError},
			{RuleID: "R3", Severity: stave.ValidationSeverityWarning},
		},
	}
	if withIssues.IsValid() {
		t.Error("IsValid() = true, want false")
	}
	if !withIssues.HasErrors() {
		t.Error("HasErrors() = false, want true")
	}
	if !withIssues.HasWarnings() {
		t.Error("HasWarnings() = false, want true")
	}
	if withIssues.IsClean() {
		t.Error("IsClean() = true, want false")
	}
	if withIssues.TotalFindings() != 3 {
		t.Errorf("TotalFindings() = %d, want 3", withIssues.TotalFindings())
	}
	if withIssues.Errors().Len() != 2 {
		t.Errorf("Errors().Len() = %d, want 2", withIssues.Errors().Len())
	}
	if withIssues.Warnings().Len() != 1 {
		t.Errorf("Warnings().Len() = %d, want 1", withIssues.Warnings().Len())
	}

	var nilResult *stave.ValidationResult
	if nilResult.IsValid() || nilResult.HasErrors() || nilResult.HasWarnings() || nilResult.IsClean() ||
		nilResult.HasCheckedControls() || nilResult.HasCheckedSnapshots() || nilResult.TotalFindings() != 0 ||
		nilResult.Errors() != nil || nilResult.Warnings() != nil {
		t.Error("nil ValidationResult should return zero/false safely")
	}
}
