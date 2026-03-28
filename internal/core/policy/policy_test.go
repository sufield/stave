package policy

import (
	"context"
	"errors"
	"testing"
)

// --- Mocks ---

type mockProjectValidator struct {
	resp ValidateResponse
	err  error
}

func (m *mockProjectValidator) Validate(_ context.Context, _, _ string) (ValidateResponse, error) {
	return m.resp, m.err
}

type mockFileValidator struct {
	resp ValidateResponse
	err  error
}

func (m *mockFileValidator) ValidateFile(_ context.Context, _, _ string) (ValidateResponse, error) {
	return m.resp, m.err
}

type mockLintRunner struct {
	resp LintResponse
	err  error
}

func (m *mockLintRunner) RunLint(_ context.Context, _ string) (LintResponse, error) {
	return m.resp, m.err
}

type mockFmtRunner struct {
	resp FmtResponse
	err  error
}

func (m *mockFmtRunner) RunFmt(_ context.Context, _ string, _ bool) (FmtResponse, error) {
	return m.resp, m.err
}

type mockReader struct {
	data []byte
	err  error
}

func (m *mockReader) ReadInput(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

type mockPolicyAnalyzer struct {
	resp InspectPolicyResponse
	err  error
}

func (m *mockPolicyAnalyzer) AnalyzePolicy(_ context.Context, _ []byte) (InspectPolicyResponse, error) {
	return m.resp, m.err
}

type mockACLAnalyzer struct {
	resp InspectACLResponse
	err  error
}

func (m *mockACLAnalyzer) AnalyzeACL(_ context.Context, _ []byte) (InspectACLResponse, error) {
	return m.resp, m.err
}

type mockExposureClassifier struct {
	resp InspectExposureResponse
	err  error
}

func (m *mockExposureClassifier) ClassifyExposure(_ context.Context, _ []byte) (InspectExposureResponse, error) {
	return m.resp, m.err
}

type mockRiskScorer struct {
	resp InspectRiskResponse
	err  error
}

func (m *mockRiskScorer) ScoreRisk(_ context.Context, _ []byte) (InspectRiskResponse, error) {
	return m.resp, m.err
}

type mockComplianceResolver struct {
	resp InspectComplianceResponse
	err  error
}

func (m *mockComplianceResolver) ResolveCrosswalk(_ context.Context, _ []byte, _, _ []string) (InspectComplianceResponse, error) {
	return m.resp, m.err
}

type mockAliasRegistry struct {
	resp InspectAliasesResponse
	err  error
}

func (m *mockAliasRegistry) ListAliases(_ context.Context, _ string) (InspectAliasesResponse, error) {
	return m.resp, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// --- Validate tests ---

func TestValidate(t *testing.T) {
	t.Run("project", func(t *testing.T) {
		_, err := Validate(context.Background(), ValidateRequest{ControlsDir: "c"}, ValidateDeps{ProjectValidator: &mockProjectValidator{resp: ValidateResponse{Valid: true}}})
		assertNoErr(t, err)
	})
	t.Run("file", func(t *testing.T) {
		_, err := Validate(context.Background(), ValidateRequest{InputFile: "f.json"}, ValidateDeps{FileValidator: &mockFileValidator{resp: ValidateResponse{Valid: true}}})
		assertNoErr(t, err)
	})
	t.Run("nil file validator", func(t *testing.T) {
		_, err := Validate(context.Background(), ValidateRequest{InputFile: "f.json"}, ValidateDeps{})
		assertErr(t, err)
	})
	t.Run("nil project validator", func(t *testing.T) {
		_, err := Validate(context.Background(), ValidateRequest{}, ValidateDeps{})
		assertErr(t, err)
	})
	t.Run("project error", func(t *testing.T) {
		_, err := Validate(context.Background(), ValidateRequest{}, ValidateDeps{ProjectValidator: &mockProjectValidator{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("file error", func(t *testing.T) {
		_, err := Validate(context.Background(), ValidateRequest{InputFile: "f.json"}, ValidateDeps{FileValidator: &mockFileValidator{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Validate(canceled(), ValidateRequest{}, ValidateDeps{ProjectValidator: &mockProjectValidator{}})
		assertCanceled(t, err)
	})
}

// --- Lint tests ---

func TestLint(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Lint(context.Background(), LintRequest{Target: "t"}, LintDeps{Runner: &mockLintRunner{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := Lint(context.Background(), LintRequest{}, LintDeps{Runner: &mockLintRunner{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Lint(context.Background(), LintRequest{Target: "t"}, LintDeps{Runner: &mockLintRunner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Lint(canceled(), LintRequest{Target: "t"}, LintDeps{Runner: &mockLintRunner{}})
		assertCanceled(t, err)
	})
}

// --- Fmt tests ---

func TestFmt(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Fmt(context.Background(), FmtRequest{Target: "t"}, FmtDeps{Runner: &mockFmtRunner{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := Fmt(context.Background(), FmtRequest{}, FmtDeps{Runner: &mockFmtRunner{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Fmt(context.Background(), FmtRequest{Target: "t"}, FmtDeps{Runner: &mockFmtRunner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Fmt(canceled(), FmtRequest{Target: "t"}, FmtDeps{Runner: &mockFmtRunner{}})
		assertCanceled(t, err)
	})
}

// --- Inspect tests ---

func TestInspectPolicy(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		_, err := InspectPolicy(context.Background(), InspectPolicyRequest{FilePath: "p.json"}, InspectPolicyDeps{Analyzer: &mockPolicyAnalyzer{}, Reader: &mockReader{data: []byte(`{}`)}})
		assertNoErr(t, err)
	})
	t.Run("stdin", func(t *testing.T) {
		_, err := InspectPolicy(context.Background(), InspectPolicyRequest{InputData: []byte(`{}`)}, InspectPolicyDeps{Analyzer: &mockPolicyAnalyzer{}, Reader: &mockReader{}})
		assertNoErr(t, err)
	})
	t.Run("no input", func(t *testing.T) {
		_, err := InspectPolicy(context.Background(), InspectPolicyRequest{}, InspectPolicyDeps{Analyzer: &mockPolicyAnalyzer{}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := InspectPolicy(context.Background(), InspectPolicyRequest{InputData: []byte(`{}`)}, InspectPolicyDeps{Analyzer: &mockPolicyAnalyzer{err: errors.New("fail")}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("reader error", func(t *testing.T) {
		_, err := InspectPolicy(context.Background(), InspectPolicyRequest{FilePath: "x"}, InspectPolicyDeps{Analyzer: &mockPolicyAnalyzer{}, Reader: &mockReader{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := InspectPolicy(canceled(), InspectPolicyRequest{FilePath: "x"}, InspectPolicyDeps{Analyzer: &mockPolicyAnalyzer{}, Reader: &mockReader{}})
		assertCanceled(t, err)
	})
}

func TestInspectACL(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := InspectACL(context.Background(), InspectACLRequest{InputData: []byte(`[]`)}, InspectACLDeps{Analyzer: &mockACLAnalyzer{}, Reader: &mockReader{}})
		assertNoErr(t, err)
	})
	t.Run("no input", func(t *testing.T) {
		_, err := InspectACL(context.Background(), InspectACLRequest{}, InspectACLDeps{Analyzer: &mockACLAnalyzer{}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := InspectACL(context.Background(), InspectACLRequest{InputData: []byte(`[]`)}, InspectACLDeps{Analyzer: &mockACLAnalyzer{err: errors.New("fail")}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := InspectACL(canceled(), InspectACLRequest{FilePath: "x"}, InspectACLDeps{Analyzer: &mockACLAnalyzer{}, Reader: &mockReader{}})
		assertCanceled(t, err)
	})
}

func TestInspectExposure(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := InspectExposure(context.Background(), InspectExposureRequest{InputData: []byte(`{}`)}, InspectExposureDeps{Classifier: &mockExposureClassifier{}, Reader: &mockReader{}})
		assertNoErr(t, err)
	})
	t.Run("no input", func(t *testing.T) {
		_, err := InspectExposure(context.Background(), InspectExposureRequest{}, InspectExposureDeps{Classifier: &mockExposureClassifier{}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := InspectExposure(context.Background(), InspectExposureRequest{InputData: []byte(`{}`)}, InspectExposureDeps{Classifier: &mockExposureClassifier{err: errors.New("fail")}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := InspectExposure(canceled(), InspectExposureRequest{FilePath: "x"}, InspectExposureDeps{Classifier: &mockExposureClassifier{}, Reader: &mockReader{}})
		assertCanceled(t, err)
	})
}

func TestInspectRisk(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := InspectRisk(context.Background(), InspectRiskRequest{InputData: []byte(`{}`)}, InspectRiskDeps{Scorer: &mockRiskScorer{}, Reader: &mockReader{}})
		assertNoErr(t, err)
	})
	t.Run("no input", func(t *testing.T) {
		_, err := InspectRisk(context.Background(), InspectRiskRequest{}, InspectRiskDeps{Scorer: &mockRiskScorer{}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := InspectRisk(context.Background(), InspectRiskRequest{InputData: []byte(`{}`)}, InspectRiskDeps{Scorer: &mockRiskScorer{err: errors.New("fail")}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := InspectRisk(canceled(), InspectRiskRequest{FilePath: "x"}, InspectRiskDeps{Scorer: &mockRiskScorer{}, Reader: &mockReader{}})
		assertCanceled(t, err)
	})
}

func TestInspectCompliance(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := InspectCompliance(context.Background(), InspectComplianceRequest{InputData: []byte(`{}`)}, InspectComplianceDeps{Resolver: &mockComplianceResolver{}, Reader: &mockReader{}})
		assertNoErr(t, err)
	})
	t.Run("no input", func(t *testing.T) {
		_, err := InspectCompliance(context.Background(), InspectComplianceRequest{}, InspectComplianceDeps{Resolver: &mockComplianceResolver{}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := InspectCompliance(context.Background(), InspectComplianceRequest{InputData: []byte(`{}`)}, InspectComplianceDeps{Resolver: &mockComplianceResolver{err: errors.New("fail")}, Reader: &mockReader{}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := InspectCompliance(canceled(), InspectComplianceRequest{FilePath: "x"}, InspectComplianceDeps{Resolver: &mockComplianceResolver{}, Reader: &mockReader{}})
		assertCanceled(t, err)
	})
}

func TestInspectAliases(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := InspectAliases(context.Background(), InspectAliasesRequest{}, InspectAliasesDeps{Registry: &mockAliasRegistry{resp: InspectAliasesResponse{SupportedOperators: []string{"eq"}}}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := InspectAliases(context.Background(), InspectAliasesRequest{}, InspectAliasesDeps{Registry: &mockAliasRegistry{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := InspectAliases(canceled(), InspectAliasesRequest{}, InspectAliasesDeps{Registry: &mockAliasRegistry{}})
		assertCanceled(t, err)
	})
}

// --- Helpers ---

func assertNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func assertCanceled(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
