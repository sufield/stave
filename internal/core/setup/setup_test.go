package setup

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestDoctorRequest_JSON(t *testing.T) {
	req := DoctorRequest{Cwd: "/home/user", Format: "text"}
	roundTrip(t, req, func(got DoctorRequest) { assertEqual(t, "Cwd", got.Cwd, "/home/user") })
}

// --- Mocks ---

type mockDoctorRunner struct {
	resp DoctorResponse
	err  error
}

func (m *mockDoctorRunner) RunChecks(_ context.Context, _ DoctorRequest) (DoctorResponse, error) {
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

func callDoctor(e error) error {
	_, err := Doctor(context.Background(), DoctorRequest{}, DoctorDeps{Runner: &mockDoctorRunner{err: e}})
	return err
}
func callDoctorCtx() error {
	_, err := Doctor(canceled(), DoctorRequest{}, DoctorDeps{Runner: &mockDoctorRunner{}})
	return err
}
