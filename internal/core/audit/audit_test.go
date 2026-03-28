package audit

import (
	"context"
	"errors"
	"testing"
)

type mockAuditRunner struct {
	resp SecurityAuditResponse
	err  error
}

func (m *mockAuditRunner) RunAudit(_ context.Context, _ SecurityAuditRequest) (SecurityAuditResponse, error) {
	return m.resp, m.err
}

type mockControlsLister struct {
	rows []ControlRow
	err  error
}

func (m *mockControlsLister) ListControls(_ context.Context, _ string, _ bool, _ []string) ([]ControlRow, error) {
	return m.rows, m.err
}

type mockCoverageComputer struct {
	data any
	err  error
}

func (m *mockCoverageComputer) ComputeCoverage(_ context.Context, _, _ string) (any, error) {
	return m.data, m.err
}

type mockExplainFinder struct {
	resp ExplainResponse
	err  error
}

func (m *mockExplainFinder) ExplainControl(_ context.Context, _, _ string) (ExplainResponse, error) {
	return m.resp, m.err
}

type mockAliasLister struct {
	names []string
	err   error
}

func (m *mockAliasLister) ListPredicateAliases(_ context.Context, _ string) ([]string, error) {
	return m.names, m.err
}

type mockAliasResolver struct {
	expanded any
	err      error
}

func (m *mockAliasResolver) ResolveAlias(_ context.Context, _ string) (any, error) {
	return m.expanded, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestSecurityAudit(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := SecurityAudit(context.Background(), SecurityAuditRequest{}, SecurityAuditDeps{Runner: &mockAuditRunner{}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := SecurityAudit(context.Background(), SecurityAuditRequest{}, SecurityAuditDeps{Runner: &mockAuditRunner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := SecurityAudit(canceled(), SecurityAuditRequest{}, SecurityAuditDeps{Runner: &mockAuditRunner{}})
		assertCanceled(t, err)
	})
}

func TestControlsList(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := ControlsList(context.Background(), ControlsListRequest{ControlsDir: "c"}, ControlsListDeps{Lister: &mockControlsLister{rows: []ControlRow{{ID: "CTL.A"}}}})
		assertNoErr(t, err)
		if len(resp.Controls) != 1 {
			t.Errorf("Controls: got %d", len(resp.Controls))
		}
	})
	t.Run("error", func(t *testing.T) {
		_, err := ControlsList(context.Background(), ControlsListRequest{}, ControlsListDeps{Lister: &mockControlsLister{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := ControlsList(canceled(), ControlsListRequest{}, ControlsListDeps{Lister: &mockControlsLister{}})
		assertCanceled(t, err)
	})
}

func TestGraphCoverage(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := GraphCoverage(context.Background(), GraphCoverageRequest{ControlsDir: "c", ObservationsDir: "o"}, GraphCoverageDeps{Computer: &mockCoverageComputer{data: "ok"}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := GraphCoverage(context.Background(), GraphCoverageRequest{}, GraphCoverageDeps{Computer: &mockCoverageComputer{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := GraphCoverage(canceled(), GraphCoverageRequest{}, GraphCoverageDeps{Computer: &mockCoverageComputer{}})
		assertCanceled(t, err)
	})
}

func TestExplain(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Explain(context.Background(), ExplainRequest{ControlID: "CTL.A"}, ExplainDeps{Finder: &mockExplainFinder{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := Explain(context.Background(), ExplainRequest{}, ExplainDeps{Finder: &mockExplainFinder{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Explain(context.Background(), ExplainRequest{ControlID: "CTL.A"}, ExplainDeps{Finder: &mockExplainFinder{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Explain(canceled(), ExplainRequest{ControlID: "CTL.A"}, ExplainDeps{Finder: &mockExplainFinder{}})
		assertCanceled(t, err)
	})
}

func TestControlsAliases(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ControlsAliases(context.Background(), ControlsAliasesRequest{}, ControlsAliasesDeps{Lister: &mockAliasLister{names: []string{"a"}}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := ControlsAliases(context.Background(), ControlsAliasesRequest{}, ControlsAliasesDeps{Lister: &mockAliasLister{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := ControlsAliases(canceled(), ControlsAliasesRequest{}, ControlsAliasesDeps{Lister: &mockAliasLister{}})
		assertCanceled(t, err)
	})
}

func TestControlsAliasExplain(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ControlsAliasExplain(context.Background(), ControlsAliasExplainRequest{Alias: "a"}, ControlsAliasExplainDeps{Resolver: &mockAliasResolver{expanded: "ok"}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := ControlsAliasExplain(context.Background(), ControlsAliasExplainRequest{}, ControlsAliasExplainDeps{Resolver: &mockAliasResolver{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := ControlsAliasExplain(context.Background(), ControlsAliasExplainRequest{Alias: "a"}, ControlsAliasExplainDeps{Resolver: &mockAliasResolver{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := ControlsAliasExplain(canceled(), ControlsAliasExplainRequest{Alias: "a"}, ControlsAliasExplainDeps{Resolver: &mockAliasResolver{}})
		assertCanceled(t, err)
	})
}

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
