package eval

import (
	"fmt"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// ControlFilter (additional cases)
// ---------------------------------------------------------------------------

func TestFilterControls_BySeverityWithMultiple(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001", Severity: controldef.SeverityCritical},
		{ID: "CTL.B.001", Severity: controldef.SeverityLow},
		{ID: "CTL.C.001", Severity: controldef.SeverityHigh},
		{ID: "CTL.D.001", Severity: controldef.SeverityInfo},
	}
	filtered, err := FilterControls(controls, ControlFilter{MinSeverity: controldef.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 2 {
		t.Fatalf("expected 2 controls (critical + high), got %d", len(filtered))
	}
}

func TestFilterControls_ByControlIDOnly(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001"},
		{ID: "CTL.B.001"},
	}
	filtered, err := FilterControls(controls, ControlFilter{ControlID: "CTL.A.001"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ID != "CTL.A.001" {
		t.Fatalf("unexpected: %v", filtered)
	}
}

func TestFilterControls_ByExcludeMultiple(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001"},
		{ID: "CTL.B.001"},
		{ID: "CTL.C.001"},
	}
	filtered, err := FilterControls(controls, ControlFilter{
		ExcludeControlID: []kernel.ControlID{"CTL.B.001", "CTL.C.001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 control, got %d", len(filtered))
	}
}

func TestFilterControls_ByComplianceFramework(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001", Compliance: controldef.ComplianceMapping{"hipaa": "164.312"}},
		{ID: "CTL.B.001", Compliance: controldef.ComplianceMapping{}},
	}
	filtered, err := FilterControls(controls, ControlFilter{Compliance: "hipaa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ID != "CTL.A.001" {
		t.Fatalf("unexpected: %v", filtered)
	}
}

func TestFilterControls_InvalidSeverityError(t *testing.T) {
	_, err := FilterControls(nil, ControlFilter{MinSeverity: controldef.Severity(99)})
	if err == nil {
		t.Fatal("expected error for invalid severity")
	}
}

func TestFilterControls_CombinedFilter(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001", Severity: controldef.SeverityCritical, Compliance: controldef.ComplianceMapping{"hipaa": "x"}},
		{ID: "CTL.B.001", Severity: controldef.SeverityCritical, Compliance: controldef.ComplianceMapping{}},
		{ID: "CTL.C.001", Severity: controldef.SeverityLow, Compliance: controldef.ComplianceMapping{"hipaa": "y"}},
	}
	filtered, err := FilterControls(controls, ControlFilter{
		MinSeverity: controldef.SeverityHigh,
		Compliance:  "hipaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ID != "CTL.A.001" {
		t.Fatalf("expected only CTL.A.001: %v", filtered)
	}
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

func TestObservationSourceStdin(t *testing.T) {
	s := ObservationSource("-")
	if !s.IsStdin() {
		t.Fatal("expected stdin")
	}
	if s.Path() != "" {
		t.Fatalf("stdin path should be empty, got %q", s.Path())
	}
}

func TestObservationSourcePath(t *testing.T) {
	s := ObservationSource("/path/to/obs")
	if s.IsStdin() {
		t.Fatal("should not be stdin")
	}
	if s.Path() != "/path/to/obs" {
		t.Fatalf("path = %q", s.Path())
	}
}

func TestOptionsValidate_Basic(t *testing.T) {
	opts := Options{
		MaxUnsafeDuration: "168h",
	}
	parsed, err := opts.Validate()
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if parsed.MaxUnsafeDuration != 168*time.Hour {
		t.Fatalf("MaxUnsafeDuration = %v", parsed.MaxUnsafeDuration)
	}
}

func TestOptionsValidate_WithNow(t *testing.T) {
	opts := Options{
		MaxUnsafeDuration: "24h",
		NowTime:           "2026-03-01T00:00:00Z",
	}
	parsed, err := opts.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Now.IsZero() {
		t.Fatal("Now should be set")
	}
}

func TestOptionsValidate_BadNow(t *testing.T) {
	opts := Options{
		MaxUnsafeDuration: "24h",
		NowTime:           "not-a-time",
	}
	_, err := opts.Validate()
	if err == nil {
		t.Fatal("expected error for bad --now")
	}
}

func TestOptionsValidate_BadDuration(t *testing.T) {
	opts := Options{
		MaxUnsafeDuration: "invalid",
	}
	_, err := opts.Validate()
	if err == nil {
		t.Fatal("expected error for invalid --max-unsafe")
	}
}

func TestOptionsValidate_IntegrityPublicKeyWithoutManifest(t *testing.T) {
	opts := Options{
		MaxUnsafeDuration:  "24h",
		IntegrityPublicKey: "key.pem",
	}
	_, err := opts.Validate()
	if err == nil {
		t.Fatal("expected error: public key without manifest")
	}
}

func TestOptionsValidate_IntegrityWithStdin(t *testing.T) {
	opts := Options{
		MaxUnsafeDuration:  "24h",
		ObservationsSource: "-",
		IntegrityManifest:  "manifest.json",
	}
	_, err := opts.Validate()
	if err == nil {
		t.Fatal("expected error: integrity with stdin")
	}
}

func TestOptionsFindConfigPath(t *testing.T) {
	opts := Options{ConfigPath: "stave.yaml"}
	path, ok := opts.FindConfigPath()
	if !ok || path != "stave.yaml" {
		t.Fatalf("FindConfigPath = (%q, %v)", path, ok)
	}

	opts = Options{}
	_, ok = opts.FindConfigPath()
	if ok {
		t.Fatal("expected false for empty ConfigPath")
	}
}

func TestOptionsFindUserConfigPath(t *testing.T) {
	opts := Options{UserConfigPath: "user.yaml"}
	path, ok := opts.FindUserConfigPath()
	if !ok || path != "user.yaml" {
		t.Fatalf("FindUserConfigPath = (%q, %v)", path, ok)
	}
}

func TestOptionsResolveContextName(t *testing.T) {
	opts := Options{ContextName: "my-project", MaxUnsafeDuration: "24h"}
	parsed, err := opts.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ContextName != "my-project" {
		t.Fatalf("ContextName = %q", parsed.ContextName)
	}
}

// ---------------------------------------------------------------------------
// NewConfig
// ---------------------------------------------------------------------------

func TestNewConfigBasic(t *testing.T) {
	plan := EvaluationPlan{
		ControlsPath:     "/controls",
		ObservationsPath: "/obs",
		ContextName:      "test",
	}
	cfg := NewConfig(plan)
	if cfg.ControlsDir != "/controls" {
		t.Fatalf("ControlsDir = %q", cfg.ControlsDir)
	}
	if cfg.Metadata.ContextName != "test" {
		t.Fatalf("ContextName = %q", cfg.Metadata.ContextName)
	}
}

func TestNewConfigWithNilOptions(t *testing.T) {
	plan := EvaluationPlan{ControlsPath: "/c", ObservationsPath: "/o"}
	// nil options should not panic
	cfg := NewConfig(plan, nil, nil)
	if cfg.ControlsDir != "/c" {
		t.Fatalf("ControlsDir = %q", cfg.ControlsDir)
	}
}

// ---------------------------------------------------------------------------
// IntentEvaluationResult
// ---------------------------------------------------------------------------

func TestIntentEvaluationResult_HasErrors(t *testing.T) {
	r := IntentEvaluationResult{}
	if r.HasErrors() {
		t.Fatal("empty result should not have errors")
	}

	r.ControlErr = fmt.Errorf("control error")
	if !r.HasErrors() {
		t.Fatal("should have errors with ControlErr set")
	}

	r = IntentEvaluationResult{ObservationErr: fmt.Errorf("obs error")}
	if !r.HasErrors() {
		t.Fatal("should have errors with ObservationErr set")
	}
}

func TestIntentEvaluationResult_FirstError(t *testing.T) {
	r := IntentEvaluationResult{}
	if r.FirstError() != nil {
		t.Fatal("empty result should return nil")
	}

	r.ControlErr = fmt.Errorf("control error")
	r.ObservationErr = fmt.Errorf("obs error")
	if r.FirstError().Error() != "control error" {
		t.Fatal("should return control error first")
	}

	r = IntentEvaluationResult{ObservationErr: fmt.Errorf("obs only")}
	if r.FirstError().Error() != "obs only" {
		t.Fatal("should return observation error when control error is nil")
	}
}
