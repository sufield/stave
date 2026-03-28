package catalog

import (
	"context"
	"errors"
	"testing"
)

type mockRegistry struct {
	packs    []PackEntry
	showResp PacksShowResponse
	listErr  error
	showErr  error
}

func (m *mockRegistry) ListPacks(_ context.Context) ([]PackEntry, error) {
	return m.packs, m.listErr
}
func (m *mockRegistry) ShowPack(_ context.Context, _ string) (PacksShowResponse, error) {
	return m.showResp, m.showErr
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestPacksList(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		resp, err := PacksList(context.Background(), PacksListRequest{}, PacksDeps{Registry: &mockRegistry{packs: []PackEntry{{Name: "s3"}}}})
		assertNoErr(t, err)
		if len(resp.Packs) != 1 {
			t.Errorf("Packs: got %d", len(resp.Packs))
		}
	})
	t.Run("error", func(t *testing.T) {
		_, err := PacksList(context.Background(), PacksListRequest{}, PacksDeps{Registry: &mockRegistry{listErr: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := PacksList(canceled(), PacksListRequest{}, PacksDeps{Registry: &mockRegistry{}})
		assertCanceled(t, err)
	})
}

func TestPacksShow(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := PacksShow(context.Background(), PacksShowRequest{Name: "s3"}, PacksDeps{Registry: &mockRegistry{showResp: PacksShowResponse{PackData: "ok"}}})
		assertNoErr(t, err)
	})
	t.Run("empty", func(t *testing.T) {
		_, err := PacksShow(context.Background(), PacksShowRequest{}, PacksDeps{Registry: &mockRegistry{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := PacksShow(context.Background(), PacksShowRequest{Name: "x"}, PacksDeps{Registry: &mockRegistry{showErr: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := PacksShow(canceled(), PacksShowRequest{Name: "s3"}, PacksDeps{Registry: &mockRegistry{}})
		assertCanceled(t, err)
	})
}

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
