package reporting

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// --- Mocks ---

type mockEvalLoader struct {
	findings []BaselineFinding
	err      error
}

func (m *mockEvalLoader) LoadFindings(_ context.Context, _ string) ([]BaselineFinding, error) {
	return m.findings, m.err
}

type mockBaselineLoader struct {
	findings []BaselineFinding
	err      error
}

func (m *mockBaselineLoader) LoadBaseline(_ context.Context, _ string) ([]BaselineFinding, error) {
	return m.findings, m.err
}

type mockBaselineWriter struct{ err error }

func (m *mockBaselineWriter) WriteBaseline(_ context.Context, _ string, _ []BaselineFinding, _ time.Time, _ string) error {
	return m.err
}

type mockReportLoader struct {
	data *safetyenvelope.Evaluation
	err  error
}

func (m *mockReportLoader) LoadEvaluation(_ context.Context, _ string) (*safetyenvelope.Evaluation, error) {
	return m.data, m.err
}

type mockEnforceGen struct {
	resp EnforceResponse
	err  error
}

func (m *mockEnforceGen) GenerateTemplate(_ context.Context, _ EnforceRequest) (EnforceResponse, error) {
	return m.resp, m.err
}

type mockPromptGen struct {
	resp PromptFromFindingResponse
	err  error
}

func (m *mockPromptGen) GeneratePrompt(_ context.Context, _ PromptFromFindingRequest) (PromptFromFindingResponse, error) {
	return m.resp, m.err
}

type mockDiagnoseRunner struct {
	data any
	err  error
}

func (m *mockDiagnoseRunner) RunDiagnosis(_ context.Context, _ DiagnoseRequest) (any, error) {
	return m.data, m.err
}

type mockDiagnoseDetail struct {
	data any
	err  error
}

func (m *mockDiagnoseDetail) RunDetail(_ context.Context, _, _, _, _ string) (any, error) {
	return m.data, m.err
}

type mockDocsSearcher struct {
	resp DocsSearchResponse
	err  error
}

func (m *mockDocsSearcher) SearchDocs(_ context.Context, _ DocsSearchRequest) (DocsSearchResponse, error) {
	return m.resp, m.err
}

type mockDocsOpener struct {
	resp DocsOpenResponse
	err  error
}

func (m *mockDocsOpener) OpenDoc(_ context.Context, _ DocsOpenRequest) (DocsOpenResponse, error) {
	return m.resp, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

var fixedClock = ports.FixedClock(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC))

// --- Baseline Save ---

func TestBaselineSave(t *testing.T) {
	findings := []BaselineFinding{{ControlID: "CTL.A", AssetID: "b"}}
	t.Run("happy", func(t *testing.T) {
		resp, err := BaselineSave(context.Background(), BaselineSaveRequest{EvaluationPath: "e.json", OutputPath: "b.json"}, BaselineSaveDeps{Loader: &mockEvalLoader{findings: findings}, Writer: &mockBaselineWriter{}, Clock: fixedClock})
		assertNoErr(t, err)
		if resp.FindingsCount != 1 {
			t.Errorf("FindingsCount: got %d", resp.FindingsCount)
		}
	})
	t.Run("load error", func(t *testing.T) {
		_, err := BaselineSave(context.Background(), BaselineSaveRequest{EvaluationPath: "e.json"}, BaselineSaveDeps{Loader: &mockEvalLoader{err: errors.New("fail")}, Writer: &mockBaselineWriter{}, Clock: fixedClock})
		assertErr(t, err)
	})
	t.Run("write error", func(t *testing.T) {
		_, err := BaselineSave(context.Background(), BaselineSaveRequest{EvaluationPath: "e.json"}, BaselineSaveDeps{Loader: &mockEvalLoader{findings: findings}, Writer: &mockBaselineWriter{err: errors.New("fail")}, Clock: fixedClock})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := BaselineSave(canceled(), BaselineSaveRequest{}, BaselineSaveDeps{Loader: &mockEvalLoader{}, Writer: &mockBaselineWriter{}, Clock: fixedClock})
		assertCanceled(t, err)
	})
}

// --- Baseline Check ---

func TestBaselineCheck(t *testing.T) {
	base := []BaselineFinding{{ControlID: "CTL.A", AssetID: "b"}}
	curr := []BaselineFinding{{ControlID: "CTL.A", AssetID: "b"}, {ControlID: "CTL.B", AssetID: "c"}}
	t.Run("happy", func(t *testing.T) {
		resp, err := BaselineCheck(context.Background(), BaselineCheckRequest{EvaluationPath: "e.json", BaselinePath: "b.json"}, BaselineCheckDeps{EvalLoader: &mockEvalLoader{findings: curr}, BaselineLoader: &mockBaselineLoader{findings: base}, Clock: fixedClock})
		assertNoErr(t, err)
		if resp.Summary.NewFindings != 1 {
			t.Errorf("NewFindings: got %d", resp.Summary.NewFindings)
		}
	})
	t.Run("eval error", func(t *testing.T) {
		_, err := BaselineCheck(context.Background(), BaselineCheckRequest{EvaluationPath: "e.json", BaselinePath: "b.json"}, BaselineCheckDeps{EvalLoader: &mockEvalLoader{err: errors.New("fail")}, BaselineLoader: &mockBaselineLoader{}, Clock: fixedClock})
		assertErr(t, err)
	})
	t.Run("baseline error", func(t *testing.T) {
		_, err := BaselineCheck(context.Background(), BaselineCheckRequest{EvaluationPath: "e.json", BaselinePath: "b.json"}, BaselineCheckDeps{EvalLoader: &mockEvalLoader{findings: curr}, BaselineLoader: &mockBaselineLoader{err: errors.New("fail")}, Clock: fixedClock})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := BaselineCheck(canceled(), BaselineCheckRequest{}, BaselineCheckDeps{EvalLoader: &mockEvalLoader{}, BaselineLoader: &mockBaselineLoader{}, Clock: fixedClock})
		assertCanceled(t, err)
	})
}

// --- CI Diff ---

func TestCIDiff(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := CIDiff(context.Background(), CIDiffRequest{CurrentPath: "c.json", BaselinePath: "b.json"}, CIDiffDeps{CurrentLoader: &mockEvalLoader{}, BaselineLoader: &mockEvalLoader{}, Clock: fixedClock})
		assertNoErr(t, err)
	})
	t.Run("current error", func(t *testing.T) {
		_, err := CIDiff(context.Background(), CIDiffRequest{CurrentPath: "c.json"}, CIDiffDeps{CurrentLoader: &mockEvalLoader{err: errors.New("fail")}, BaselineLoader: &mockEvalLoader{}, Clock: fixedClock})
		assertErr(t, err)
	})
	t.Run("baseline error", func(t *testing.T) {
		_, err := CIDiff(context.Background(), CIDiffRequest{CurrentPath: "c.json", BaselinePath: "b.json"}, CIDiffDeps{CurrentLoader: &mockEvalLoader{}, BaselineLoader: &mockEvalLoader{err: errors.New("fail")}, Clock: fixedClock})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := CIDiff(canceled(), CIDiffRequest{}, CIDiffDeps{CurrentLoader: &mockEvalLoader{}, BaselineLoader: &mockEvalLoader{}, Clock: fixedClock})
		assertCanceled(t, err)
	})
}

// --- Report ---

func TestReport(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Report(context.Background(), ReportRequest{InputFile: "e.json"}, ReportDeps{Loader: &mockReportLoader{data: &safetyenvelope.Evaluation{}}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Report(context.Background(), ReportRequest{InputFile: "e.json"}, ReportDeps{Loader: &mockReportLoader{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Report(canceled(), ReportRequest{}, ReportDeps{Loader: &mockReportLoader{}})
		assertCanceled(t, err)
	})
}

// --- Enforce ---

func TestEnforce(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Enforce(context.Background(), EnforceRequest{InputPath: "e.json", Mode: "pab"}, EnforceDeps{Generator: &mockEnforceGen{}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Enforce(context.Background(), EnforceRequest{}, EnforceDeps{Generator: &mockEnforceGen{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Enforce(canceled(), EnforceRequest{}, EnforceDeps{Generator: &mockEnforceGen{}})
		assertCanceled(t, err)
	})
}

// --- PromptFromFinding ---

func TestPromptFromFinding(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := PromptFromFinding(context.Background(), PromptFromFindingRequest{EvaluationFile: "e", AssetID: "a"}, PromptFromFindingDeps{Generator: &mockPromptGen{}})
		assertNoErr(t, err)
	})
	t.Run("empty eval", func(t *testing.T) {
		_, err := PromptFromFinding(context.Background(), PromptFromFindingRequest{AssetID: "a"}, PromptFromFindingDeps{Generator: &mockPromptGen{}})
		assertErr(t, err)
	})
	t.Run("empty asset", func(t *testing.T) {
		_, err := PromptFromFinding(context.Background(), PromptFromFindingRequest{EvaluationFile: "e"}, PromptFromFindingDeps{Generator: &mockPromptGen{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := PromptFromFinding(context.Background(), PromptFromFindingRequest{EvaluationFile: "e", AssetID: "a"}, PromptFromFindingDeps{Generator: &mockPromptGen{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := PromptFromFinding(canceled(), PromptFromFindingRequest{EvaluationFile: "e", AssetID: "a"}, PromptFromFindingDeps{Generator: &mockPromptGen{}})
		assertCanceled(t, err)
	})
}

// --- Diagnose ---

func TestDiagnose(t *testing.T) {
	t.Run("summary", func(t *testing.T) {
		_, err := Diagnose(context.Background(), DiagnoseRequest{}, DiagnoseDeps{Runner: &mockDiagnoseRunner{data: "ok"}, Detail: &mockDiagnoseDetail{}})
		assertNoErr(t, err)
	})
	t.Run("detail", func(t *testing.T) {
		resp, err := Diagnose(context.Background(), DiagnoseRequest{ControlID: "CTL.A", AssetID: "b"}, DiagnoseDeps{Runner: &mockDiagnoseRunner{}, Detail: &mockDiagnoseDetail{data: "detail"}})
		assertNoErr(t, err)
		if !resp.IsDetailMode {
			t.Error("expected detail mode")
		}
	})
	t.Run("runner error", func(t *testing.T) {
		_, err := Diagnose(context.Background(), DiagnoseRequest{}, DiagnoseDeps{Runner: &mockDiagnoseRunner{err: errors.New("fail")}, Detail: &mockDiagnoseDetail{}})
		assertErr(t, err)
	})
	t.Run("detail error", func(t *testing.T) {
		_, err := Diagnose(context.Background(), DiagnoseRequest{ControlID: "CTL.A", AssetID: "b"}, DiagnoseDeps{Runner: &mockDiagnoseRunner{}, Detail: &mockDiagnoseDetail{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Diagnose(canceled(), DiagnoseRequest{}, DiagnoseDeps{Runner: &mockDiagnoseRunner{}, Detail: &mockDiagnoseDetail{}})
		assertCanceled(t, err)
	})
}

// --- DocsSearch ---

func TestDocsSearch(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := DocsSearch(context.Background(), DocsSearchRequest{Query: "q", MaxResults: 10}, DocsSearchDeps{Searcher: &mockDocsSearcher{}})
		assertNoErr(t, err)
	})
	t.Run("empty query", func(t *testing.T) {
		_, err := DocsSearch(context.Background(), DocsSearchRequest{MaxResults: 10}, DocsSearchDeps{Searcher: &mockDocsSearcher{}})
		assertErr(t, err)
	})
	t.Run("bad max", func(t *testing.T) {
		_, err := DocsSearch(context.Background(), DocsSearchRequest{Query: "q", MaxResults: 0}, DocsSearchDeps{Searcher: &mockDocsSearcher{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := DocsSearch(context.Background(), DocsSearchRequest{Query: "q", MaxResults: 10}, DocsSearchDeps{Searcher: &mockDocsSearcher{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := DocsSearch(canceled(), DocsSearchRequest{Query: "q", MaxResults: 10}, DocsSearchDeps{Searcher: &mockDocsSearcher{}})
		assertCanceled(t, err)
	})
}

// --- DocsOpen ---

func TestDocsOpen(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := DocsOpen(context.Background(), DocsOpenRequest{Topic: "t"}, DocsOpenDeps{Opener: &mockDocsOpener{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := DocsOpen(context.Background(), DocsOpenRequest{}, DocsOpenDeps{Opener: &mockDocsOpener{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := DocsOpen(context.Background(), DocsOpenRequest{Topic: "t"}, DocsOpenDeps{Opener: &mockDocsOpener{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := DocsOpen(canceled(), DocsOpenRequest{Topic: "t"}, DocsOpenDeps{Opener: &mockDocsOpener{}})
		assertCanceled(t, err)
	})
}

// --- Mid-function cancellation tests ---

// cancelingLoader cancels the context after returning successfully,
// so the mid-function ctx.Err() check fires.
type cancelingLoader struct {
	findings []BaselineFinding
	cancel   context.CancelFunc
}

func (m *cancelingLoader) LoadFindings(_ context.Context, _ string) ([]BaselineFinding, error) {
	m.cancel()
	return m.findings, nil
}

func TestBaselineSave_MidCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	loader := &cancelingLoader{findings: []BaselineFinding{{ControlID: "A"}}, cancel: cancel}
	_, err := BaselineSave(ctx, BaselineSaveRequest{EvaluationPath: "e.json"}, BaselineSaveDeps{Loader: loader, Writer: &mockBaselineWriter{}, Clock: fixedClock})
	assertCanceled(t, err)
}

func TestBaselineCheck_MidCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	loader := &cancelingLoader{findings: []BaselineFinding{}, cancel: cancel}
	_, err := BaselineCheck(ctx, BaselineCheckRequest{EvaluationPath: "e.json", BaselinePath: "b.json"}, BaselineCheckDeps{EvalLoader: loader, BaselineLoader: &mockBaselineLoader{}, Clock: fixedClock})
	assertCanceled(t, err)
}

func TestCIDiff_MidCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	loader := &cancelingLoader{findings: []BaselineFinding{}, cancel: cancel}
	_, err := CIDiff(ctx, CIDiffRequest{CurrentPath: "c.json", BaselinePath: "b.json"}, CIDiffDeps{CurrentLoader: loader, BaselineLoader: &mockEvalLoader{}, Clock: fixedClock})
	assertCanceled(t, err)
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
