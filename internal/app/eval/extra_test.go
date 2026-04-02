package eval

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/sanitize"
)

func TestObservationSource_IsStdin(t *testing.T) {
	if !(ObservationSource("-")).IsStdin() {
		t.Error("'-' should be stdin")
	}
	if (ObservationSource("./obs")).IsStdin() {
		t.Error("'./obs' should not be stdin")
	}
}

func TestObservationSource_Path(t *testing.T) {
	if ObservationSource("-").Path() != "" {
		t.Error("stdin path should be empty")
	}
	if ObservationSource("./obs").Path() != "./obs" {
		t.Errorf("Path() = %q", ObservationSource("./obs").Path())
	}
}

func TestOptions_Validate_ValidOptions(t *testing.T) {
	parsed, err := Options{
		MaxUnsafeDuration: "24h",
		NowTime:           "2026-01-15T00:00:00Z",
		ContextName:       "test",
	}.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if parsed.MaxUnsafeDuration != 24*time.Hour {
		t.Errorf("MaxUnsafeDuration = %v", parsed.MaxUnsafeDuration)
	}
	if parsed.Now.IsZero() {
		t.Error("Now should be set")
	}
	if parsed.ContextName != "test" {
		t.Errorf("ContextName = %q", parsed.ContextName)
	}
}

func TestOptions_Validate_InvalidDuration(t *testing.T) {
	_, err := Options{MaxUnsafeDuration: "not-a-duration"}.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid --max-unsafe") {
		t.Fatalf("expected max-unsafe error, got: %v", err)
	}
}

func TestOptions_Validate_InvalidNowTime(t *testing.T) {
	_, err := Options{
		MaxUnsafeDuration: "24h",
		NowTime:           "not-a-time",
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid timestamp") {
		t.Fatalf("expected timestamp error, got: %v", err)
	}
}

func TestOptions_Validate_NoNowTime(t *testing.T) {
	parsed, err := Options{MaxUnsafeDuration: "24h"}.Validate()
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if !parsed.Now.IsZero() {
		t.Error("Now should be zero when --now not set")
	}
}

func TestOptions_Validate_IntegrityFlagConflict(t *testing.T) {
	_, err := Options{
		MaxUnsafeDuration:  "24h",
		IntegrityPublicKey: "/key.pem",
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "requires integrity-manifest") {
		t.Fatalf("expected flag conflict error, got: %v", err)
	}
}

func TestOptions_Validate_IntegrityStdinConflict(t *testing.T) {
	_, err := Options{
		MaxUnsafeDuration:  "24h",
		ObservationsSource: "-",
		IntegrityManifest:  "/manifest.json",
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "stdin mode") {
		t.Fatalf("expected stdin conflict error, got: %v", err)
	}
}

func TestOptions_Validate_IntegrityManifestNotFound(t *testing.T) {
	_, err := Options{
		MaxUnsafeDuration: "24h",
		IntegrityManifest: "/nonexistent/manifest.json",
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got: %v", err)
	}
}

func TestOptions_Validate_IntegrityManifestIsDir(t *testing.T) {
	dir := t.TempDir()
	_, err := Options{
		MaxUnsafeDuration: "24h",
		IntegrityManifest: dir,
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be a file") {
		t.Fatalf("expected 'must be a file' error, got: %v", err)
	}
}

func TestOptions_ResolveContextName_EmptyProjectRoot(t *testing.T) {
	// With empty project root, resolveContextName uses filepath.Abs("") which
	// returns the current working directory's basename. Just test it doesn't panic.
	o := Options{ContextName: "", ProjectRoot: ""}
	got := o.resolveContextName()
	if got == "" {
		t.Error("resolveContextName() should not be empty")
	}
}

func TestOptions_ResolveContextName_FromProjectRoot(t *testing.T) {
	dir := t.TempDir()
	o := Options{ContextName: "", ProjectRoot: dir}
	got := o.resolveContextName()
	expected := filepath.Base(dir)
	if got != expected {
		t.Errorf("resolveContextName() = %q, want %q", got, expected)
	}
}

func TestOptions_ResolveContextName_Explicit(t *testing.T) {
	o := Options{ContextName: "custom"}
	got := o.resolveContextName()
	if got != "custom" {
		t.Errorf("resolveContextName() = %q", got)
	}
}

func TestOptions_FindConfigPath(t *testing.T) {
	o := Options{ConfigPath: "/my/config.yaml"}
	path, ok := o.FindConfigPath()
	if !ok || path != "/my/config.yaml" {
		t.Errorf("FindConfigPath() = %q, %v", path, ok)
	}

	o2 := Options{}
	_, ok2 := o2.FindConfigPath()
	if ok2 {
		t.Error("expected false for empty config path")
	}
}

func TestOptions_FindUserConfigPath(t *testing.T) {
	o := Options{UserConfigPath: "/my/user.yaml"}
	path, ok := o.FindUserConfigPath()
	if !ok || path != "/my/user.yaml" {
		t.Errorf("FindUserConfigPath() = %q, %v", path, ok)
	}
}

func TestResolveLockPath(t *testing.T) {
	if got := resolveLockPath(""); got != "" {
		t.Errorf("resolveLockPath('') = %q", got)
	}
	if got := resolveLockPath("/project"); got != "/project/stave.lock" {
		t.Errorf("resolveLockPath('/project') = %q", got)
	}
}

func TestControlFilter_Enabled(t *testing.T) {
	if (ControlFilter{}).Enabled() {
		t.Error("empty filter should not be enabled")
	}
	if !(ControlFilter{ControlID: "CTL.A"}).Enabled() {
		t.Error("filter with ControlID should be enabled")
	}
	if !(ControlFilter{Compliance: "cis"}).Enabled() {
		t.Error("filter with Compliance should be enabled")
	}
	if !(ControlFilter{ExcludeControlID: []kernel.ControlID{"CTL.A"}}).Enabled() {
		t.Error("filter with ExcludeControlID should be enabled")
	}
}

func TestFilterControls_ExcludeByID(t *testing.T) {
	invs := sampleControlDefs()
	got, err := FilterControls(invs, ControlFilter{ExcludeControlID: []kernel.ControlID{"CTL.B"}})
	if err != nil {
		t.Fatalf("FilterControls() error = %v", err)
	}
	if len(got) != 1 || got[0].ID != "CTL.A" {
		t.Fatalf("filtered = %v", got)
	}
}

func TestPrepareFindings_NilEnricher(t *testing.T) {
	_, err := PrepareFindings(nil, nil, evaluation.Result{})
	if err == nil || !strings.Contains(err.Error(), "must not be nil") {
		t.Fatalf("expected must not be nil error, got: %v", err)
	}
}

func TestSanitizeFindings_WithSanitizer(t *testing.T) {
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{AssetID: "res-1"}},
		{Finding: evaluation.Finding{AssetID: "res-2"}},
	}
	s := sanitize.New(sanitize.WithIDSanitization(true))
	result := SanitizeFindings(s, findings)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	// IDs should be sanitized (not equal to originals)
	if result[0].AssetID == "res-1" {
		t.Error("expected sanitized asset ID")
	}
}

func TestSanitizeInputHashKeys_Nil(t *testing.T) {
	result := SanitizeInputHashKeys(nil, nil)
	if result != nil {
		t.Error("expected nil for nil input")
	}
}

func TestSanitizeExemptedAssets_Empty(t *testing.T) {
	result := SanitizeExemptedAssets(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty, got %d", len(result))
	}
}

func TestEnrich_NilSanitizer(t *testing.T) {
	enricher := remediation.NewMapper(crypto.NewHasher())
	result := evaluation.Result{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Now:               time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		},
		ExemptedAssets: []asset.ExemptedAsset{
			{ID: "res-1", Reason: "test"},
		},
	}
	enriched, err := Enrich(enricher, nil, result)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}
	if len(enriched.ExemptedAssets) != 1 {
		t.Errorf("ExemptedAssets = %v", enriched.ExemptedAssets)
	}
}

func TestResolveOutputWriters(t *testing.T) {
	out, stderr := resolveOutputWriters(nil, nil)
	if out == nil || stderr == nil {
		t.Fatal("expected non-nil writers")
	}
}

func TestValidateBuildDependenciesInput_EmptyPlan(t *testing.T) {
	err := validateBuildDependenciesInput(BuildDependenciesInput{})
	if err == nil || !strings.Contains(err.Error(), "evaluation plan is required") {
		t.Fatalf("expected plan error, got: %v", err)
	}
}

func TestApplyDeps_Close(t *testing.T) {
	d := &ApplyDeps{}
	d.Close() // just ensure no panic
}

func TestValidateFilePath_Empty(t *testing.T) {
	if err := validateFilePath("", "test"); err != nil {
		t.Errorf("expected nil for empty path, got: %v", err)
	}
}

func TestValidateFilePath_NotExist(t *testing.T) {
	err := validateFilePath("/nonexistent/file", "test")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got: %v", err)
	}
}

func TestValidateFilePath_IsDir(t *testing.T) {
	err := validateFilePath(t.TempDir(), "test")
	if err == nil || !strings.Contains(err.Error(), "must be a file") {
		t.Fatalf("expected 'must be a file', got: %v", err)
	}
}

func TestValidateFilePath_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	os.WriteFile(path, []byte("x"), 0o600)
	if err := validateFilePath(path, "test"); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestOutputPipeline_Run_Success(t *testing.T) {
	var buf bytes.Buffer
	pipeline := &OutputPipeline{
		Marshaler: &marshalerStub{},
		Enricher: func(result evaluation.Result) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{Result: result}, nil
		},
	}
	result := evaluation.Result{Summary: evaluation.Summary{Violations: 0}}
	err := pipeline.Run(context.Background(), &buf, result)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected output")
	}
}

func TestOutputPipeline_Run_EnrichError(t *testing.T) {
	var buf bytes.Buffer
	pipeline := &OutputPipeline{
		Marshaler: &marshalerStub{},
		Enricher: func(result evaluation.Result) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{}, fmt.Errorf("enrich failed")
		},
	}
	err := pipeline.Run(context.Background(), &buf, evaluation.Result{})
	if err == nil || !strings.Contains(err.Error(), "enrich") {
		t.Fatalf("expected enrich error, got: %v", err)
	}
}

func TestOutputPipeline_Run_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	var buf bytes.Buffer
	pipeline := &OutputPipeline{
		Marshaler: &marshalerStub{},
		Enricher: func(result evaluation.Result) (appcontracts.EnrichedResult, error) {
			return appcontracts.EnrichedResult{Result: result}, nil
		},
	}
	err := pipeline.Run(ctx, &buf, evaluation.Result{})
	if err == nil {
		t.Fatal("expected context cancelled error")
	}
}

func TestRunDirectoryEvaluation_NilLoader(t *testing.T) {
	_, _, err := RunDirectoryEvaluation(DirectoryEvaluationRequest{})
	if err == nil || !strings.Contains(err.Error(), "observation loader is required") {
		t.Fatalf("expected nil loader error, got: %v", err)
	}
}

func sampleControlDefs() []policy.ControlDefinition {
	return []policy.ControlDefinition{
		{ID: "CTL.A", Severity: policy.SeverityCritical},
		{ID: "CTL.B", Severity: policy.SeverityLow},
	}
}
