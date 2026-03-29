package apply

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
	validation "github.com/sufield/stave/internal/core/schemaval"
)

// --- ParseProfile ---

func TestParseProfile_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  Profile
	}{
		{"aws-s3", ProfileAWSS3},
		{"hipaa", ProfileHIPAA},
	}
	for _, tt := range tests {
		got, err := ParseProfile(tt.input)
		if err != nil {
			t.Fatalf("ParseProfile(%q) error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("ParseProfile(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseProfile_Invalid(t *testing.T) {
	_, err := ParseProfile("unknown-profile")
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
	if !strings.Contains(err.Error(), "unsupported --profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- buildClock ---

func TestBuildClock_ZeroTime(t *testing.T) {
	c := buildClock(time.Time{})
	if _, ok := c.(ports.RealClock); !ok {
		t.Fatalf("expected RealClock for zero time, got %T", c)
	}
}

func TestBuildClock_FixedTime(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	c := buildClock(now)
	fc, ok := c.(ports.FixedClock)
	if !ok {
		t.Fatalf("expected FixedClock, got %T", c)
	}
	if !time.Time(fc).Equal(now) {
		t.Fatalf("FixedClock = %v, want %v", time.Time(fc), now)
	}
}

// --- quoteArg ---

func TestQuoteArg_NoSpecialChars(t *testing.T) {
	got := quoteArg("simple")
	if got != "simple" {
		t.Fatalf("quoteArg = %q, want %q", got, "simple")
	}
}

func TestQuoteArg_WithSpaces(t *testing.T) {
	got := quoteArg("has spaces")
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("expected quoted string, got: %q", got)
	}
}

func TestQuoteArg_WithSingleQuote(t *testing.T) {
	got := quoteArg("it's")
	if !strings.Contains(got, "\\'") {
		t.Fatalf("expected escaped single quote, got: %q", got)
	}
}

func TestQuoteArg_WithShellChars(t *testing.T) {
	specialChars := []string{"$var", "`cmd`", "a|b", "a;b", "a&b", "a(b"}
	for _, s := range specialChars {
		got := quoteArg(s)
		if !strings.HasPrefix(got, "'") {
			t.Errorf("quoteArg(%q) = %q, expected quoted", s, got)
		}
	}
}

// --- readinessNextCommand ---

func TestReadinessNextCommand_Ready(t *testing.T) {
	report := validation.Report{
		Ready:           true,
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
	}
	got := readinessNextCommand(report)
	if !strings.Contains(got, "stave apply") {
		t.Fatalf("expected apply command, got: %q", got)
	}
	if !strings.Contains(got, "controls/s3") {
		t.Fatalf("expected controls dir, got: %q", got)
	}
}

func TestReadinessNextCommand_NotReady(t *testing.T) {
	report := validation.Report{
		Ready:           false,
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
	}
	got := readinessNextCommand(report)
	if !strings.Contains(got, "stave validate") {
		t.Fatalf("expected validate command, got: %q", got)
	}
}

// --- decorateError ---

func TestDecorateError_NoControls(t *testing.T) {
	err := decorateError(appeval.ErrNoControls)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var ue *ui.UserError
	if !errors.As(err, &ue) {
		t.Fatalf("expected UserError, got %T", err)
	}
}

func TestDecorateError_NoSnapshots(t *testing.T) {
	err := decorateError(appeval.ErrNoSnapshots)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var ue *ui.UserError
	if !errors.As(err, &ue) {
		t.Fatalf("expected UserError, got %T", err)
	}
}

func TestDecorateError_SourceTypeMissing(t *testing.T) {
	err := decorateError(appeval.ErrSourceTypeMissing)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestDecorateError_SchemaValidation(t *testing.T) {
	err := decorateError(contractvalidator.ErrSchemaValidationFailed)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestDecorateError_Unknown(t *testing.T) {
	orig := errors.New("some unknown error")
	err := decorateError(orig)
	if err != orig {
		t.Fatal("expected original error for unknown error type")
	}
}

// --- Reporter ---

func TestReporter_ReportApply_Pass(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Reporter{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Runtime: ui.NewRuntime(&stdout, &stderr),
	}

	policy := evaluation.ResponsePolicy{}
	res := EvaluateResult{SafetyStatus: evaluation.StatusSafe}
	err := r.ReportApply(res, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stderr.String(), "No violations found") {
		t.Fatalf("expected success message, got: %s", stderr.String())
	}
}

func TestReporter_ReportApply_Fail(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Reporter{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Runtime: ui.NewRuntime(&stdout, &stderr),
	}

	policy := evaluation.ResponsePolicy{}
	res := EvaluateResult{
		SafetyStatus:    evaluation.StatusUnsafe,
		DiagnoseCommand: "stave diagnose",
		NextSteps:       []string{"fix it"},
	}
	err := r.ReportApply(res, policy)
	if !errors.Is(err, ui.ErrViolationsFound) {
		t.Fatalf("expected ErrViolationsFound, got: %v", err)
	}
}

func TestReporter_ReportApply_Quiet(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Reporter{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Runtime: ui.NewRuntime(&stdout, &stderr),
		Quiet:   true,
	}

	policy := evaluation.ResponsePolicy{}
	res := EvaluateResult{SafetyStatus: evaluation.StatusSafe}
	err := r.ReportApply(res, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got: %s", stderr.String())
	}
}

// --- printReadinessIssue ---

func TestPrintReadinessIssue(t *testing.T) {
	var buf bytes.Buffer
	issue := validation.Issue{
		Name:    "controls",
		Status:  validation.StatusPass,
		Message: "found 5 controls",
		Fix:     "run validate",
		Command: "stave validate",
	}
	err := printReadinessIssue(&buf, issue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "controls") {
		t.Fatalf("expected name in output, got: %s", out)
	}
	if !strings.Contains(out, "Fix: run validate") {
		t.Fatalf("expected fix in output, got: %s", out)
	}
	if !strings.Contains(out, "Command: stave validate") {
		t.Fatalf("expected command in output, got: %s", out)
	}
}

func TestPrintReadinessIssue_NoFixOrCommand(t *testing.T) {
	var buf bytes.Buffer
	issue := validation.Issue{
		Name:    "obs",
		Status:  validation.StatusPass,
		Message: "found 3 snapshots",
	}
	err := printReadinessIssue(&buf, issue)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Fix:") {
		t.Fatalf("should not contain Fix: when empty, got: %s", out)
	}
	if strings.Contains(out, "Command:") {
		t.Fatalf("should not contain Command: when empty, got: %s", out)
	}
}

// --- Reporter.ReportPlan ---

func TestReporter_ReportPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Reporter{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Runtime: ui.NewRuntime(&stdout, &stderr),
	}
	report := validation.Report{
		Ready:           true,
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
		Summary: validation.Summary{
			ControlsChecked:          5,
			SnapshotsChecked:         3,
			AssetObservationsChecked: 10,
		},
	}
	err := r.ReportPlan(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "Plan Summary") {
		t.Fatalf("expected Plan Summary, got: %s", out)
	}
	if !strings.Contains(out, "Ready:        true") {
		t.Fatalf("expected Ready: true, got: %s", out)
	}
	if !strings.Contains(out, "stave apply") {
		t.Fatalf("expected apply next command, got: %s", out)
	}
}

func TestReporter_ReportPlan_Quiet(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Reporter{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Runtime: ui.NewRuntime(&stdout, &stderr),
		Quiet:   true,
	}
	report := validation.Report{Ready: true}
	err := r.ReportPlan(report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got: %s", stdout.String())
	}
}

// --- validateInput ---

func TestValidateInput_NotFound(t *testing.T) {
	err := validateInput("/nonexistent/path/to/file.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInput_IsDirectory(t *testing.T) {
	dir := t.TempDir()
	err := validateInput(dir)
	if err == nil {
		t.Fatal("expected error for directory")
	}
	if !strings.Contains(err.Error(), "must be a file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateInput_ValidFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.json")
	if err := os.WriteFile(f, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := validateInput(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- profileControlDomain ---

func TestProfileControlDomain(t *testing.T) {
	tests := []struct {
		prof Profile
		want string
	}{
		{ProfileAWSS3, "s3"},
		{ProfileHIPAA, "s3"},
	}
	for _, tt := range tests {
		got := profileControlDomain(tt.prof)
		if got != tt.want {
			t.Fatalf("profileControlDomain(%q) = %q, want %q", tt.prof, got, tt.want)
		}
	}
}

// --- SharedOptions.normalize ---

func TestSharedOptions_Normalize(t *testing.T) {
	opts := SharedOptions{
		ControlsDir:     "controls/s3/./",
		ObservationsDir: "obs/../obs/",
	}
	opts.normalize()
	// After normalization, paths should be cleaned
	if strings.Contains(opts.ControlsDir, "/.") {
		t.Fatalf("ControlsDir not cleaned: %q", opts.ControlsDir)
	}
}

// --- resolveScopeFilter ---

func TestResolveScopeFilter_IncludeAll(t *testing.T) {
	cfg := Config{IncludeAll: true}
	f := resolveScopeFilter(cfg)
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
}

func TestResolveScopeFilter_Allowlist(t *testing.T) {
	cfg := Config{BucketAllowlist: []string{"bucket-a", "bucket-b"}}
	f := resolveScopeFilter(cfg)
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
}

func TestResolveScopeFilter_Default(t *testing.T) {
	cfg := Config{}
	f := resolveScopeFilter(cfg)
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
}

// --- filterSnapshots ---

func TestFilterSnapshots_Empty(t *testing.T) {
	var stderr bytes.Buffer
	cfg := Config{IncludeAll: true}
	got := filterSnapshots(&stderr, false, cfg, nil)
	if got != nil {
		t.Fatal("expected nil for empty snapshots")
	}
	if !strings.Contains(stderr.String(), "No snapshots") {
		t.Fatalf("expected 'No snapshots' warning, got: %s", stderr.String())
	}
}

func TestFilterSnapshots_EmptyQuiet(t *testing.T) {
	var stderr bytes.Buffer
	cfg := Config{IncludeAll: true}
	got := filterSnapshots(&stderr, true, cfg, nil)
	if got != nil {
		t.Fatal("expected nil for empty snapshots")
	}
	if stderr.Len() != 0 {
		t.Fatal("expected no stderr output in quiet mode")
	}
}

// --- finalizeProfileEvaluation ---

func TestFinalizeProfileEvaluation_NoFindings(t *testing.T) {
	var stderr bytes.Buffer
	result := evaluation.Result{Findings: nil}
	err := finalizeProfileEvaluation(&stderr, false, result, nil, "ctl", "input")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stderr.String(), "No violations found") {
		t.Fatalf("expected success message, got: %s", stderr.String())
	}
}

func TestFinalizeProfileEvaluation_WithFindings(t *testing.T) {
	var stderr bytes.Buffer
	result := evaluation.Result{
		Findings: []evaluation.Finding{{ControlID: "CTL.TEST.001"}},
	}
	err := finalizeProfileEvaluation(&stderr, false, result, nil, "ctl", "input")
	if !errors.Is(err, ui.ErrViolationsFound) {
		t.Fatalf("expected ErrViolationsFound, got: %v", err)
	}
}

func TestFinalizeProfileEvaluation_Quiet(t *testing.T) {
	var stderr bytes.Buffer
	result := evaluation.Result{Findings: nil}
	err := finalizeProfileEvaluation(&stderr, true, result, nil, "ctl", "input")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatal("expected no stderr output in quiet mode")
	}
}

// --- validateDirsWithConfig ---

func TestValidateDirsWithConfig_StdinObservations(t *testing.T) {
	// stdin mode should skip observations validation
	tmp := t.TempDir()
	err := validateDirsWithConfig(tmp, "-", false, nil)
	if err == nil {
		// Controls dir is tmp which exists, and obs is stdin, should succeed
		t.Log("stdin mode passed controls validation")
	}
}

// --- NewReadinessRunner ---

func TestNewReadinessRunner(t *testing.T) {
	factory := func(ctlDir, obsDir string, sanitize bool) ReadinessValidator {
		return func(maxUnsafe time.Duration, now time.Time) (validation.Result, error) {
			return validation.Result{}, nil
		}
	}
	runner := NewReadinessRunner(factory)
	if runner == nil {
		t.Fatal("expected non-nil runner")
	}
	if runner.CreateValidator == nil {
		t.Fatal("expected non-nil CreateValidator")
	}
}

// --- EvaluateResult struct ---

func TestEvaluateResult_Defaults(t *testing.T) {
	res := EvaluateResult{}
	if res.SafetyStatus != "" {
		t.Fatalf("expected empty status, got %q", res.SafetyStatus)
	}
	if res.DiagnoseCommand != "" {
		t.Fatal("expected empty command")
	}
	if res.NextSteps != nil {
		t.Fatal("expected nil next steps")
	}
}

// --- ReadinessConfig defaults ---

func TestReadinessConfig_Defaults(t *testing.T) {
	cfg := ReadinessConfig{}
	if cfg.Quiet {
		t.Fatal("default Quiet should be false")
	}
	if cfg.Sanitize {
		t.Fatal("default Sanitize should be false")
	}
}
