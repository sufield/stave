package setup

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// --- Type serialization tests ---

func TestDoctorRequest_JSON(t *testing.T) {
	req := DoctorRequest{Cwd: "/home/user", Format: "text"}
	roundTrip(t, req, func(got DoctorRequest) { assertEqual(t, "Cwd", got.Cwd, "/home/user") })
}

func TestInitRequest_JSON(t *testing.T) {
	req := InitRequest{Dir: "/tmp", Profile: "aws-s3", DryRun: true}
	roundTrip(t, req, func(got InitRequest) { assertEqual(t, "Profile", got.Profile, "aws-s3") })
}

func TestAliasSetRequest_JSON(t *testing.T) {
	req := AliasSetRequest{Name: "ev", Command: "apply"}
	roundTrip(t, req, func(got AliasSetRequest) { assertEqual(t, "Name", got.Name, "ev") })
}

func TestContextCreateRequest_JSON(t *testing.T) {
	req := ContextCreateRequest{Name: "proj", Dir: "/tmp"}
	roundTrip(t, req, func(got ContextCreateRequest) { assertEqual(t, "Name", got.Name, "proj") })
}

func TestConfigGetResponse_JSON(t *testing.T) {
	resp := ConfigGetResponse{Key: "max_unsafe", Value: "168h", Source: "stave.yaml"}
	roundTrip(t, resp, func(got ConfigGetResponse) { assertEqual(t, "Value", got.Value, "168h") })
}

// --- Mocks ---

type mockDoctorRunner struct {
	resp DoctorResponse
	err  error
}

func (m *mockDoctorRunner) RunChecks(_ context.Context, _ DoctorRequest) (DoctorResponse, error) {
	return m.resp, m.err
}

type mockStatusScanner struct {
	resp StatusResponse
	err  error
}

func (m *mockStatusScanner) ScanStatus(_ context.Context, _ StatusRequest) (StatusResponse, error) {
	return m.resp, m.err
}

type mockScaffolder struct {
	resp InitResponse
	err  error
}

func (m *mockScaffolder) ScaffoldProject(_ context.Context, _ InitRequest) (InitResponse, error) {
	return m.resp, m.err
}

type mockConfigResolver struct {
	data any
	err  error
}

func (m *mockConfigResolver) ResolveEffectiveConfig(_ context.Context) (any, error) {
	return m.data, m.err
}

type mockConfigReader struct {
	resp ConfigGetResponse
	err  error
}

func (m *mockConfigReader) GetConfig(_ context.Context, _ string) (ConfigGetResponse, error) {
	return m.resp, m.err
}

type mockConfigWriter struct {
	setErr, delErr error
}

func (m *mockConfigWriter) SetConfig(_ context.Context, _, _ string) error { return m.setErr }
func (m *mockConfigWriter) DeleteConfig(_ context.Context, _ string) error { return m.delErr }

type mockEnvLister struct {
	resp EnvListResponse
	err  error
}

func (m *mockEnvLister) ListEnvVars(_ context.Context) (EnvListResponse, error) {
	return m.resp, m.err
}

type mockAliasStore struct {
	entries                 []AliasEntry
	setErr, listErr, delErr error
}

func (m *mockAliasStore) SetAlias(_ context.Context, _, _ string) error { return m.setErr }
func (m *mockAliasStore) ListAliases(_ context.Context) ([]AliasEntry, error) {
	return m.entries, m.listErr
}
func (m *mockAliasStore) DeleteAlias(_ context.Context, _ string) error { return m.delErr }

type mockContextStore struct {
	entries                                     []ContextEntry
	showResp                                    ContextShowResponse
	createErr, listErr, useErr, showErr, delErr error
}

func (m *mockContextStore) CreateContext(_ context.Context, _ ContextCreateRequest) error {
	return m.createErr
}
func (m *mockContextStore) ListContexts(_ context.Context) ([]ContextEntry, error) {
	return m.entries, m.listErr
}
func (m *mockContextStore) UseContext(_ context.Context, _ string) error { return m.useErr }
func (m *mockContextStore) ShowContext(_ context.Context) (ContextShowResponse, error) {
	return m.showResp, m.showErr
}
func (m *mockContextStore) DeleteContext(_ context.Context, _ string) error { return m.delErr }

type mockControlGenerator struct {
	resp GenerateControlResponse
	err  error
}

func (m *mockControlGenerator) GenerateControl(_ context.Context, _ GenerateControlRequest) (GenerateControlResponse, error) {
	return m.resp, m.err
}

type mockObservationGenerator struct {
	resp GenerateObservationResponse
	err  error
}

func (m *mockObservationGenerator) GenerateObservation(_ context.Context, _ GenerateObservationRequest) (GenerateObservationResponse, error) {
	return m.resp, m.err
}

// --- Doctor tests ---

func TestDoctor(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := Doctor(context.Background(), DoctorRequest{}, DoctorDeps{Runner: &mockDoctorRunner{resp: DoctorResponse{AllPassed: true}}})
		assertNoErr(t, err)
		if !resp.AllPassed {
			t.Error("AllPassed: got false")
		}
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callDoctor(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callDoctorCtx()) })
}

// --- Status tests ---

func TestStatus(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := Status(context.Background(), StatusRequest{}, StatusDeps{Scanner: &mockStatusScanner{resp: StatusResponse{NextCommand: "apply"}}})
		assertNoErr(t, err)
		assertEqual(t, "NextCommand", resp.NextCommand, "apply")
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callStatus(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callStatusCtx()) })
}

// --- Init tests ---

func TestInit(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Init(context.Background(), InitRequest{Dir: "/tmp"}, InitDeps{Scaffolder: &mockScaffolder{resp: InitResponse{BaseDir: "/tmp"}}})
		assertNoErr(t, err)
	})
	t.Run("empty dir", func(t *testing.T) { assertErr(t, callInit(InitRequest{Dir: ""})) })
	t.Run("bad profile", func(t *testing.T) { assertErr(t, callInit(InitRequest{Dir: "/tmp", Profile: "gcp"})) })
	t.Run("bad cadence", func(t *testing.T) { assertErr(t, callInit(InitRequest{Dir: "/tmp", CaptureCadence: "weekly"})) })
	t.Run("error", func(t *testing.T) { assertErr(t, callInitErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callInitCtx()) })
}

// --- ConfigShow tests ---

func TestConfigShow(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := ConfigShow(context.Background(), ConfigShowRequest{}, ConfigShowDeps{Resolver: &mockConfigResolver{data: "ok"}})
		assertNoErr(t, err)
		if resp.ConfigData == nil {
			t.Error("ConfigData: got nil")
		}
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callConfigShow(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callConfigShowCtx()) })
}

// --- ConfigGet/Set/Delete tests ---

func TestConfigGet(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := ConfigGet(context.Background(), ConfigGetRequest{Key: "k"}, ConfigGetDeps{Reader: &mockConfigReader{resp: ConfigGetResponse{Key: "k", Value: "v"}}})
		assertNoErr(t, err)
		assertEqual(t, "Value", resp.Value, "v")
	})
	t.Run("empty key", func(t *testing.T) { assertErr(t, callConfigGet("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callConfigGetErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callConfigGetCtx()) })
}

func TestConfigSet(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ConfigSet(context.Background(), ConfigSetRequest{Key: "k", Value: "v"}, ConfigSetDeps{Writer: &mockConfigWriter{}})
		assertNoErr(t, err)
	})
	t.Run("empty key", func(t *testing.T) { assertErr(t, callConfigSet("", "v")) })
	t.Run("empty value", func(t *testing.T) { assertErr(t, callConfigSet("k", "")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callConfigSetErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callConfigSetCtx()) })
}

func TestConfigDelete(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ConfigDelete(context.Background(), ConfigDeleteRequest{Key: "k"}, ConfigDeleteDeps{Writer: &mockConfigWriter{}})
		assertNoErr(t, err)
	})
	t.Run("empty key", func(t *testing.T) { assertErr(t, callConfigDel("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callConfigDelErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callConfigDelCtx()) })
}

// --- EnvList tests ---

func TestEnvList(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := EnvList(context.Background(), EnvListRequest{}, EnvListDeps{Lister: &mockEnvLister{resp: EnvListResponse{Entries: []EnvEntry{{Name: "A"}}}}})
		assertNoErr(t, err)
		if len(resp.Entries) != 1 {
			t.Errorf("Entries: got %d", len(resp.Entries))
		}
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callEnvList(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callEnvListCtx()) })
}

// --- Alias tests ---

func TestAliasSet(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := AliasSet(context.Background(), AliasSetRequest{Name: "ev", Command: "apply"}, AliasDeps{Store: &mockAliasStore{}})
		assertNoErr(t, err)
	})
	t.Run("bad name", func(t *testing.T) { assertErr(t, callAliasSet("ev!!", "apply")) })
	t.Run("empty cmd", func(t *testing.T) { assertErr(t, callAliasSet("ev", "")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callAliasSetErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callAliasSetCtx()) })
}

func TestAliasList(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := AliasList(context.Background(), AliasListRequest{}, AliasDeps{Store: &mockAliasStore{entries: []AliasEntry{{Name: "ev"}}}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callAliasListErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callAliasListCtx()) })
}

func TestAliasDelete(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := AliasDelete(context.Background(), AliasDeleteRequest{Name: "ev"}, AliasDeps{Store: &mockAliasStore{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callAliasDel("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callAliasDelErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callAliasDelCtx()) })
}

// --- Context tests ---

func TestContextCreate(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ContextCreate(context.Background(), ContextCreateRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callCtxCreate("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callCtxCreateErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callCtxCreateCtx()) })
}

func TestContextList(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ContextList(context.Background(), ContextListRequest{}, ContextDeps{Store: &mockContextStore{}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callCtxListErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callCtxListCtx()) })
}

func TestContextUse(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ContextUse(context.Background(), ContextUseRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callCtxUse("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callCtxUseErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callCtxUseCtx()) })
}

func TestContextShow(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ContextShow(context.Background(), ContextShowRequest{}, ContextDeps{Store: &mockContextStore{showResp: ContextShowResponse{Name: "p"}}})
		assertNoErr(t, err)
	})
	t.Run("error", func(t *testing.T) { assertErr(t, callCtxShowErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callCtxShowCtx()) })
}

func TestContextDelete(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := ContextDelete(context.Background(), ContextDeleteRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callCtxDel("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callCtxDelErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callCtxDelCtx()) })
}

// --- Generate tests ---

func TestGenerateControl(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := GenerateControl(context.Background(), GenerateControlRequest{Name: "ctl"}, GenerateControlDeps{Generator: &mockControlGenerator{resp: GenerateControlResponse{OutputPath: "a.yaml"}}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callGenCtl("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callGenCtlErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callGenCtlCtx()) })
}

func TestGenerateObservation(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := GenerateObservation(context.Background(), GenerateObservationRequest{Name: "obs"}, GenerateObservationDeps{Generator: &mockObservationGenerator{resp: GenerateObservationResponse{OutputPath: "a.json"}}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) { assertErr(t, callGenObs("")) })
	t.Run("error", func(t *testing.T) { assertErr(t, callGenObsErr(errors.New("fail"))) })
	t.Run("ctx", func(t *testing.T) { assertCanceled(t, callGenObsCtx()) })
}

// --- Test helpers ---

func roundTrip[T any](t *testing.T, v T, check func(T)) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got T
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	check(got)
}

func assertEqual(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q, want %q", field, got, want)
	}
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

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// --- Shorthand callers to reduce line noise ---

func callDoctor(e error) error {
	_, err := Doctor(context.Background(), DoctorRequest{}, DoctorDeps{Runner: &mockDoctorRunner{err: e}})
	return err
}
func callDoctorCtx() error {
	_, err := Doctor(canceled(), DoctorRequest{}, DoctorDeps{Runner: &mockDoctorRunner{}})
	return err
}
func callStatus(e error) error {
	_, err := Status(context.Background(), StatusRequest{}, StatusDeps{Scanner: &mockStatusScanner{err: e}})
	return err
}
func callStatusCtx() error {
	_, err := Status(canceled(), StatusRequest{}, StatusDeps{Scanner: &mockStatusScanner{}})
	return err
}
func callInit(req InitRequest) error {
	_, err := Init(context.Background(), req, InitDeps{Scaffolder: &mockScaffolder{}})
	return err
}
func callInitErr(e error) error {
	_, err := Init(context.Background(), InitRequest{Dir: "/tmp"}, InitDeps{Scaffolder: &mockScaffolder{err: e}})
	return err
}
func callInitCtx() error {
	_, err := Init(canceled(), InitRequest{Dir: "/tmp"}, InitDeps{Scaffolder: &mockScaffolder{}})
	return err
}
func callConfigShow(e error) error {
	_, err := ConfigShow(context.Background(), ConfigShowRequest{}, ConfigShowDeps{Resolver: &mockConfigResolver{err: e}})
	return err
}
func callConfigShowCtx() error {
	_, err := ConfigShow(canceled(), ConfigShowRequest{}, ConfigShowDeps{Resolver: &mockConfigResolver{}})
	return err
}
func callConfigGet(key string) error {
	_, err := ConfigGet(context.Background(), ConfigGetRequest{Key: key}, ConfigGetDeps{Reader: &mockConfigReader{}})
	return err
}
func callConfigGetErr(e error) error {
	_, err := ConfigGet(context.Background(), ConfigGetRequest{Key: "k"}, ConfigGetDeps{Reader: &mockConfigReader{err: e}})
	return err
}
func callConfigGetCtx() error {
	_, err := ConfigGet(canceled(), ConfigGetRequest{Key: "k"}, ConfigGetDeps{Reader: &mockConfigReader{}})
	return err
}
func callConfigSet(k, v string) error {
	_, err := ConfigSet(context.Background(), ConfigSetRequest{Key: k, Value: v}, ConfigSetDeps{Writer: &mockConfigWriter{}})
	return err
}
func callConfigSetErr(e error) error {
	_, err := ConfigSet(context.Background(), ConfigSetRequest{Key: "k", Value: "v"}, ConfigSetDeps{Writer: &mockConfigWriter{setErr: e}})
	return err
}
func callConfigSetCtx() error {
	_, err := ConfigSet(canceled(), ConfigSetRequest{Key: "k", Value: "v"}, ConfigSetDeps{Writer: &mockConfigWriter{}})
	return err
}
func callConfigDel(key string) error {
	_, err := ConfigDelete(context.Background(), ConfigDeleteRequest{Key: key}, ConfigDeleteDeps{Writer: &mockConfigWriter{}})
	return err
}
func callConfigDelErr(e error) error {
	_, err := ConfigDelete(context.Background(), ConfigDeleteRequest{Key: "k"}, ConfigDeleteDeps{Writer: &mockConfigWriter{delErr: e}})
	return err
}
func callConfigDelCtx() error {
	_, err := ConfigDelete(canceled(), ConfigDeleteRequest{Key: "k"}, ConfigDeleteDeps{Writer: &mockConfigWriter{}})
	return err
}
func callEnvList(e error) error {
	_, err := EnvList(context.Background(), EnvListRequest{}, EnvListDeps{Lister: &mockEnvLister{err: e}})
	return err
}
func callEnvListCtx() error {
	_, err := EnvList(canceled(), EnvListRequest{}, EnvListDeps{Lister: &mockEnvLister{}})
	return err
}
func callAliasSet(name, cmd string) error {
	_, err := AliasSet(context.Background(), AliasSetRequest{Name: name, Command: cmd}, AliasDeps{Store: &mockAliasStore{}})
	return err
}
func callAliasSetErr(e error) error {
	_, err := AliasSet(context.Background(), AliasSetRequest{Name: "ev", Command: "apply"}, AliasDeps{Store: &mockAliasStore{setErr: e}})
	return err
}
func callAliasSetCtx() error {
	_, err := AliasSet(canceled(), AliasSetRequest{Name: "ev", Command: "apply"}, AliasDeps{Store: &mockAliasStore{}})
	return err
}
func callAliasListErr(e error) error {
	_, err := AliasList(context.Background(), AliasListRequest{}, AliasDeps{Store: &mockAliasStore{listErr: e}})
	return err
}
func callAliasListCtx() error {
	_, err := AliasList(canceled(), AliasListRequest{}, AliasDeps{Store: &mockAliasStore{}})
	return err
}
func callAliasDel(name string) error {
	_, err := AliasDelete(context.Background(), AliasDeleteRequest{Name: name}, AliasDeps{Store: &mockAliasStore{}})
	return err
}
func callAliasDelErr(e error) error {
	_, err := AliasDelete(context.Background(), AliasDeleteRequest{Name: "ev"}, AliasDeps{Store: &mockAliasStore{delErr: e}})
	return err
}
func callAliasDelCtx() error {
	_, err := AliasDelete(canceled(), AliasDeleteRequest{Name: "ev"}, AliasDeps{Store: &mockAliasStore{}})
	return err
}
func callCtxCreate(name string) error {
	_, err := ContextCreate(context.Background(), ContextCreateRequest{Name: name}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxCreateErr(e error) error {
	_, err := ContextCreate(context.Background(), ContextCreateRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{createErr: e}})
	return err
}
func callCtxCreateCtx() error {
	_, err := ContextCreate(canceled(), ContextCreateRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxListErr(e error) error {
	_, err := ContextList(context.Background(), ContextListRequest{}, ContextDeps{Store: &mockContextStore{listErr: e}})
	return err
}
func callCtxListCtx() error {
	_, err := ContextList(canceled(), ContextListRequest{}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxUse(name string) error {
	_, err := ContextUse(context.Background(), ContextUseRequest{Name: name}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxUseErr(e error) error {
	_, err := ContextUse(context.Background(), ContextUseRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{useErr: e}})
	return err
}
func callCtxUseCtx() error {
	_, err := ContextUse(canceled(), ContextUseRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxShowErr(e error) error {
	_, err := ContextShow(context.Background(), ContextShowRequest{}, ContextDeps{Store: &mockContextStore{showErr: e}})
	return err
}
func callCtxShowCtx() error {
	_, err := ContextShow(canceled(), ContextShowRequest{}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxDel(name string) error {
	_, err := ContextDelete(context.Background(), ContextDeleteRequest{Name: name}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callCtxDelErr(e error) error {
	_, err := ContextDelete(context.Background(), ContextDeleteRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{delErr: e}})
	return err
}
func callCtxDelCtx() error {
	_, err := ContextDelete(canceled(), ContextDeleteRequest{Name: "p"}, ContextDeps{Store: &mockContextStore{}})
	return err
}
func callGenCtl(name string) error {
	_, err := GenerateControl(context.Background(), GenerateControlRequest{Name: name}, GenerateControlDeps{Generator: &mockControlGenerator{}})
	return err
}
func callGenCtlErr(e error) error {
	_, err := GenerateControl(context.Background(), GenerateControlRequest{Name: "c"}, GenerateControlDeps{Generator: &mockControlGenerator{err: e}})
	return err
}
func callGenCtlCtx() error {
	_, err := GenerateControl(canceled(), GenerateControlRequest{Name: "c"}, GenerateControlDeps{Generator: &mockControlGenerator{}})
	return err
}
func callGenObs(name string) error {
	_, err := GenerateObservation(context.Background(), GenerateObservationRequest{Name: name}, GenerateObservationDeps{Generator: &mockObservationGenerator{}})
	return err
}
func callGenObsErr(e error) error {
	_, err := GenerateObservation(context.Background(), GenerateObservationRequest{Name: "o"}, GenerateObservationDeps{Generator: &mockObservationGenerator{err: e}})
	return err
}
func callGenObsCtx() error {
	_, err := GenerateObservation(canceled(), GenerateObservationRequest{Name: "o"}, GenerateObservationDeps{Generator: &mockObservationGenerator{}})
	return err
}
