package validatecmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
)

// testLabel is a minimal stand-in for ui.SeverityLabel (which the engine
// cannot import). The exact label format is irrelevant to these tests, which
// assert on JSON fields, hints, and exit sentinels rather than label text.
func testLabel(level, message string, _ io.Writer) string {
	return level + " " + message
}

// testReporter builds a Reporter writing to buf.
func testReporter(buf *bytes.Buffer, jsonOutput, fixHints bool) *Reporter {
	format := "text"
	if jsonOutput {
		format = "json"
	}
	return &Reporter{
		Writer:   buf,
		Format:   format,
		FixHints: fixHints,
		Label:    testLabel,
		Template: testExec,
	}
}

func TestOutputAndExit_Clean(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{}},
		Summary:     appvalidation.Summary{ControlsLoaded: 2, SnapshotsLoaded: 3, AssetObservationsLoaded: 10},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, false, false)
	if err := r.Write(result, hintContext{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := r.ExitStatus(result); err != nil {
		t.Errorf("expected nil error for clean validation, got %v", err)
	}
}

func TestOutputAndExit_Errors(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{
			{RuleID: diag.RuleControlMissingID, Severity: diag.SeverityError, Remediation: "Add id field"},
		}},
		Summary: appvalidation.Summary{ControlsLoaded: 1},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, false, false)
	if err := r.Write(result, hintContext{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := r.ExitStatus(result); !errors.Is(err, appcontracts.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed, got %v", err)
	}
}

func TestOutputAndExit_WarningsOnly(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{
			{RuleID: diag.RuleSingleSnapshot, Severity: diag.SeverityWarn, Remediation: "Add more snapshots"},
			{RuleID: diag.RuleSpanLessThanMaxUnsafe, Severity: diag.SeverityWarn, Remediation: "Reduce max-unsafe"},
		}},
		Summary: appvalidation.Summary{SnapshotsLoaded: 1},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, false, false)
	if err := r.Write(result, hintContext{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := r.ExitStatus(result); !errors.Is(err, appcontracts.ErrValidationWarnings) {
		t.Errorf("expected ErrValidationWarnings, got %v", err)
	}
}

func TestOutputAndExit_ErrorsAndWarnings(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{
			{RuleID: diag.RuleControlMissingID, Severity: diag.SeverityError, Remediation: "Add id field"},
			{RuleID: diag.RuleSingleSnapshot, Severity: diag.SeverityWarn, Remediation: "Add more snapshots"},
		}},
		Summary: appvalidation.Summary{ControlsLoaded: 1, SnapshotsLoaded: 1},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, false, false)
	if err := r.Write(result, hintContext{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if err := r.ExitStatus(result); !errors.Is(err, appcontracts.ErrValidationFailed) {
		t.Errorf("expected ErrValidationFailed (errors take precedence), got %v", err)
	}
}

func TestOutputAndExit_JSONOutput(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{
			{
				RuleID:      diag.RuleSingleSnapshot,
				Severity:    diag.SeverityWarn,
				Resource:    kernel.NewSanitizableMap(map[string]string{"snapshot_count": "1"}),
				Remediation: "Add more snapshots",
			},
		}},
		Summary: appvalidation.Summary{SnapshotsLoaded: 1},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, true, false)
	if err := r.Write(result, hintContext{}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, `"schema_version": "lint.v0.1"`) {
		t.Errorf("expected JSON to contain schema_version, got %s", output)
	}
	if !strings.Contains(output, `"valid": true`) {
		t.Errorf("expected JSON to contain 'valid': true, got %s", output)
	}
	if !strings.Contains(output, `"rule_id": "SINGLE_SNAPSHOT"`) {
		t.Errorf("expected JSON to contain warning rule_id, got %s", output)
	}
	if err := r.ExitStatus(result); !errors.Is(err, appcontracts.ErrValidationWarnings) {
		t.Errorf("expected ErrValidationWarnings, got %v", err)
	}
}

func TestWriteValidationText_WithFixHints(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{
			{
				RuleID:      diag.RuleObservationLoadFailed,
				Severity:    diag.SeverityError,
				Remediation: "Check observations",
				Resource:    kernel.NewSanitizableMap(map[string]string{"directory": "./observations"}),
			},
		}},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, false, true)
	if err := r.Write(result, hintContext{ControlsDir: "./controls", ObservationsDir: "./observations"}); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Suggested next commands:") {
		t.Fatalf("expected fix hints section, got: %s", out)
	}
	if !strings.Contains(out, "Place observation JSON files") {
		t.Fatalf("expected observation hint, got: %s", out)
	}
}

func TestOutputAndExit_JSONOutput_WithFixHints(t *testing.T) {
	result := &appvalidation.Report{
		Diagnostics: &diag.Assessment{Findings: []diag.Finding{
			{
				RuleID:      "INVALID_MAX_UNSAFE",
				Severity:    diag.SeverityError,
				Remediation: "Use valid duration",
				FixCommand:  "stave lint --max-unsafe 168h",
			},
		}},
	}
	var buf bytes.Buffer
	r := testReporter(&buf, true, true)
	_ = r.Write(result, hintContext{})
	out := buf.String()
	if !strings.Contains(out, `"fix_hints"`) {
		t.Fatalf("expected fix_hints in json output, got: %s", out)
	}
	if !strings.Contains(out, "stave lint --max-unsafe 168h") {
		t.Fatalf("expected command hint in json output, got: %s", out)
	}
}
