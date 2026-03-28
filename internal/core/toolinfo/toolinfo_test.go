package toolinfo

import (
	"context"
	"errors"
	"testing"
)

type mockVersionProvider struct {
	resp VersionResponse
	err  error
}

func (m *mockVersionProvider) GetVersion(_ context.Context, _ bool) (VersionResponse, error) {
	return m.resp, m.err
}

type mockCapProvider struct {
	resp CapabilitiesResponse
	err  error
}

func (m *mockCapProvider) GetCapabilities(_ context.Context) (CapabilitiesResponse, error) {
	return m.resp, m.err
}

type mockSchemaProvider struct {
	resp SchemasResponse
	err  error
}

func (m *mockSchemaProvider) GetSchemas(_ context.Context) (SchemasResponse, error) {
	return m.resp, m.err
}

type mockBundleGen struct {
	resp BugReportResponse
	err  error
}

func (m *mockBundleGen) GenerateBundle(_ context.Context, _ BugReportRequest) (BugReportResponse, error) {
	return m.resp, m.err
}

type mockInspector struct {
	resp BugReportInspectResponse
	err  error
}

func (m *mockInspector) InspectBundle(_ context.Context, _ string) (BugReportInspectResponse, error) {
	return m.resp, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestVersion(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		run(t, func() error {
			_, e := Version(context.Background(), VersionRequest{}, VersionDeps{Provider: &mockVersionProvider{resp: VersionResponse{VersionData: "v1"}}})
			return e
		})
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callVersion(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callVersionCtx()) })
}

func TestCapabilities(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		run(t, func() error {
			_, e := Capabilities(context.Background(), CapabilitiesRequest{}, CapabilitiesDeps{Provider: &mockCapProvider{resp: CapabilitiesResponse{CapabilitiesData: "ok"}}})
			return e
		})
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callCap(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callCapCtx()) })
}

func TestSchemas(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		run(t, func() error {
			_, e := Schemas(context.Background(), SchemasRequest{}, SchemasDeps{Provider: &mockSchemaProvider{resp: SchemasResponse{SchemasData: "ok"}}})
			return e
		})
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callSchema(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callSchemaCtx()) })
}

func TestBugReport(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		run(t, func() error {
			_, e := BugReport(context.Background(), BugReportRequest{TailLines: 100}, BugReportDeps{Generator: &mockBundleGen{}})
			return e
		})
	})
	t.Run("negative tail", func(t *testing.T) { assertErr(t, callBR(BugReportRequest{TailLines: -1})) })
	t.Run("error", func(t *testing.T) { assertErr(t, callBRErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callBRCtx()) })
}

func TestBugReportInspect(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		run(t, func() error {
			_, e := BugReportInspect(context.Background(), BugReportInspectRequest{BundlePath: "x"}, BugReportInspectDeps{Inspector: &mockInspector{}})
			return e
		})
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callBRI("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callBRIErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callBRICtx()) })
}

// --- Helpers ---

func run(t *testing.T, fn func() error) { t.Helper(); assertNoErr(t, fn()) }
func assertNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}
func assertErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
}
func assertCanceled(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want Canceled, got: %v", err)
	}
}

func callVersion(e error) error {
	_, err := Version(context.Background(), VersionRequest{}, VersionDeps{Provider: &mockVersionProvider{err: e}})
	return err
}
func callVersionCtx() error {
	_, err := Version(canceled(), VersionRequest{}, VersionDeps{Provider: &mockVersionProvider{}})
	return err
}
func callCap(e error) error {
	_, err := Capabilities(context.Background(), CapabilitiesRequest{}, CapabilitiesDeps{Provider: &mockCapProvider{err: e}})
	return err
}
func callCapCtx() error {
	_, err := Capabilities(canceled(), CapabilitiesRequest{}, CapabilitiesDeps{Provider: &mockCapProvider{}})
	return err
}
func callSchema(e error) error {
	_, err := Schemas(context.Background(), SchemasRequest{}, SchemasDeps{Provider: &mockSchemaProvider{err: e}})
	return err
}
func callSchemaCtx() error {
	_, err := Schemas(canceled(), SchemasRequest{}, SchemasDeps{Provider: &mockSchemaProvider{}})
	return err
}
func callBR(req BugReportRequest) error {
	_, err := BugReport(context.Background(), req, BugReportDeps{Generator: &mockBundleGen{}})
	return err
}
func callBRErr(e error) error {
	_, err := BugReport(context.Background(), BugReportRequest{TailLines: 1}, BugReportDeps{Generator: &mockBundleGen{err: e}})
	return err
}
func callBRCtx() error {
	_, err := BugReport(canceled(), BugReportRequest{TailLines: 1}, BugReportDeps{Generator: &mockBundleGen{}})
	return err
}
func callBRI(p string) error {
	_, err := BugReportInspect(context.Background(), BugReportInspectRequest{BundlePath: p}, BugReportInspectDeps{Inspector: &mockInspector{}})
	return err
}
func callBRIErr(e error) error {
	_, err := BugReportInspect(context.Background(), BugReportInspectRequest{BundlePath: "x"}, BugReportInspectDeps{Inspector: &mockInspector{err: e}})
	return err
}
func callBRICtx() error {
	_, err := BugReportInspect(canceled(), BugReportInspectRequest{BundlePath: "x"}, BugReportInspectDeps{Inspector: &mockInspector{}})
	return err
}
