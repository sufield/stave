package apply

import (
	"bytes"
	"errors"
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
		{"cis-aws-v3.0", ProfileCISv3},
		{"soc2", ProfileSOC2},
		{"pci-dss-v4.0", ProfilePCIDSSv4},
		{"nist-800-53", ProfileNIST},
		{"fedramp", ProfileFedRAMP},
		{"gdpr", ProfileGDPR},
		{"ffiec", ProfileFFIEC},
		{"iso-27001", ProfileISO27001},
		{"nist-csf-2.0", ProfileNISTCSF},
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
	report := validation.ReadinessAssessment{
		IsSafe:            true,
		ControlSource:     "controls/s3",
		ObservationSource: "observations",
	}
	got := report.NextCommand()
	if !strings.Contains(got, "stave apply") {
		t.Fatalf("expected apply command, got: %q", got)
	}
	if !strings.Contains(got, "controls/s3") {
		t.Fatalf("expected controls dir, got: %q", got)
	}
}

func TestReadinessNextCommand_NotReady(t *testing.T) {
	report := validation.ReadinessAssessment{
		IsSafe:            false,
		ControlSource:     "controls/s3",
		ObservationSource: "observations",
	}
	got := report.NextCommand()
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

func TestDecorateError_SchemaValidation(t *testing.T) {
	err := decorateError(contractvalidator.ErrSchemaValidationFailed)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
}

func TestDecorateError_Unknown(t *testing.T) {
	orig := errors.New("some unknown error")
	err := decorateError(orig)
	if err != orig { //nolint:errorlint // identity check: decorateError returns same pointer for unknown errors
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

	policy := evaluation.EnforcementPolicy{}
	res := EvaluateResult{SecurityState: evaluation.StateCompliant}
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

	policy := evaluation.EnforcementPolicy{}
	res := EvaluateResult{
		SecurityState:   evaluation.StateNonCompliant,
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

	policy := evaluation.EnforcementPolicy{}
	res := EvaluateResult{SecurityState: evaluation.StateCompliant}
	err := r.ReportApply(res, policy)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got: %s", stderr.String())
	}
}

// TestReporter_ReportApply_QuietStillGates locks in the contract that
// run_standard.go's --new-only path relies on: with Quiet=true and an
// NON_COMPLIANT result, ReportApply must still return ErrViolationsFound
// so the CLI exits non-zero. The new-only path uses Quiet=true on the
// gate Reporter to suppress the duplicate user-facing summary while
// preserving exit-code gating.
func TestReporter_ReportApply_QuietStillGates(t *testing.T) {
	var stdout, stderr bytes.Buffer
	r := &Reporter{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Runtime: ui.NewRuntime(&stdout, &stderr),
		Quiet:   true,
	}
	res := EvaluateResult{SecurityState: evaluation.StateNonCompliant}
	err := r.ReportApply(res, evaluation.EnforcementPolicy{})
	if !errors.Is(err, ui.ErrViolationsFound) {
		t.Fatalf("expected ErrViolationsFound under Quiet=true, got: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no output in quiet mode, got: %s", stderr.String())
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

// --- EvaluateResult struct ---

func TestEvaluateResult_Defaults(t *testing.T) {
	res := EvaluateResult{}
	if res.SecurityState != "" {
		t.Fatalf("expected empty status, got %q", res.SecurityState)
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

// --- ParseProfiles ---

func TestParseProfiles_Single(t *testing.T) {
	profiles, err := ParseProfiles("hipaa")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 1 || profiles[0] != ProfileHIPAA {
		t.Fatalf("expected [hipaa], got %v", profiles)
	}
}

func TestParseProfiles_Multiple(t *testing.T) {
	profiles, err := ParseProfiles("hipaa,soc2,pci-dss-v4.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d", len(profiles))
	}
	if profiles[0] != ProfileHIPAA || profiles[1] != ProfileSOC2 || profiles[2] != ProfilePCIDSSv4 {
		t.Fatalf("unexpected profiles: %v", profiles)
	}
}

func TestParseProfiles_Whitespace(t *testing.T) {
	profiles, err := ParseProfiles(" hipaa , soc2 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
}

func TestParseProfiles_Empty(t *testing.T) {
	_, err := ParseProfiles("")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
	if !strings.Contains(err.Error(), "no valid profiles") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseProfiles_InvalidInList(t *testing.T) {
	_, err := ParseProfiles("hipaa,bogus,soc2")
	if err == nil {
		t.Fatal("expected error for invalid profile in list")
	}
	if !strings.Contains(err.Error(), "unsupported --profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseProfiles_TrailingComma(t *testing.T) {
	profiles, err := ParseProfiles("hipaa,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile (trailing comma ignored), got %d", len(profiles))
	}
}

// --- checkSLAPolicy ---

func TestCheckSLAPolicy_WarnNeverFails(t *testing.T) {
	var stderr bytes.Buffer
	r := &Reporter{Stderr: &stderr}
	res := EvaluateResult{HasSLABreach: true, HasCriticalSLABreach: true}
	err := r.CheckSLAPolicy("warn", res)
	if err != nil {
		t.Fatalf("warn should never fail, got: %v", err)
	}
}

func TestCheckSLAPolicy_StrictFailsOnAnyBreach(t *testing.T) {
	var stderr bytes.Buffer
	r := &Reporter{Stderr: &stderr}
	res := EvaluateResult{HasSLABreach: true}
	err := r.CheckSLAPolicy("strict", res)
	if !errors.Is(err, ui.ErrViolationsFound) {
		t.Fatalf("strict should fail on SLA breach, got: %v", err)
	}
}

func TestCheckSLAPolicy_StrictPassesWhenNoBreach(t *testing.T) {
	var stderr bytes.Buffer
	r := &Reporter{Stderr: &stderr}
	res := EvaluateResult{HasSLABreach: false}
	err := r.CheckSLAPolicy("strict", res)
	if err != nil {
		t.Fatalf("strict should pass when no breach, got: %v", err)
	}
}

func TestCheckSLAPolicy_CriticalOnlyFailsOnCritical(t *testing.T) {
	var stderr bytes.Buffer
	r := &Reporter{Stderr: &stderr}
	res := EvaluateResult{HasSLABreach: true, HasCriticalSLABreach: true}
	err := r.CheckSLAPolicy("critical-only", res)
	if !errors.Is(err, ui.ErrViolationsFound) {
		t.Fatalf("critical-only should fail on critical breach, got: %v", err)
	}
}

func TestCheckSLAPolicy_CriticalOnlyPassesOnNonCritical(t *testing.T) {
	var stderr bytes.Buffer
	r := &Reporter{Stderr: &stderr}
	res := EvaluateResult{HasSLABreach: true, HasCriticalSLABreach: false}
	err := r.CheckSLAPolicy("critical-only", res)
	if err != nil {
		t.Fatalf("critical-only should pass on non-critical breach, got: %v", err)
	}
}

// TestRunNewOnly_BadNowIsFatal pins the contract that --now parse
// failures in new-only mode produce a UserError. The earlier shape
// silently fell back to time.Now() on parse failure, hiding typos
// behind output that looked correct but was anchored to wall time.
func TestRunNewOnly_BadNowIsFatal(t *testing.T) {
	var stdout bytes.Buffer
	opts := &Options{
		SharedOptions: SharedOptions{NowTime: "not-a-date"},
		HistoryDir:    t.TempDir(),
	}
	err := runNewOnlyOutput(t.Context(), &stdout, &stdout, opts, EvaluateResult{})
	if err == nil {
		t.Fatal("expected error for malformed --now, got nil")
	}
	var ue *ui.UserError
	if !errors.As(err, &ue) {
		t.Fatalf("expected ui.UserError, got %T: %v", err, err)
	}
}
