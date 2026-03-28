package manifest

import (
	"context"
	"errors"
	"testing"
)

type mockGenerator struct {
	resp GenerateResponse
	err  error
}

func (m *mockGenerator) GenerateManifest(_ context.Context, _ GenerateRequest) (GenerateResponse, error) {
	return m.resp, m.err
}

type mockSigner struct {
	resp SignResponse
	err  error
}

func (m *mockSigner) SignManifest(_ context.Context, _ SignRequest) (SignResponse, error) {
	return m.resp, m.err
}

type mockKeypairGen struct {
	resp KeygenResponse
	err  error
}

func (m *mockKeypairGen) GenerateKeypair(_ context.Context, _ KeygenRequest) (KeygenResponse, error) {
	return m.resp, m.err
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestGenerate(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Generate(context.Background(), GenerateRequest{ObservationsDir: "obs"}, GenerateDeps{Generator: &mockGenerator{resp: GenerateResponse{FileCount: 5}}})
		assertNoErr(t, err)
	})
	t.Run("empty dir", func(t *testing.T) {
		_, err := Generate(context.Background(), GenerateRequest{}, GenerateDeps{Generator: &mockGenerator{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Generate(context.Background(), GenerateRequest{ObservationsDir: "obs"}, GenerateDeps{Generator: &mockGenerator{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Generate(canceled(), GenerateRequest{ObservationsDir: "obs"}, GenerateDeps{Generator: &mockGenerator{}})
		assertCanceled(t, err)
	})
}

func TestSign(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Sign(context.Background(), SignRequest{InPath: "m.json", PrivateKeyPath: "k.pem"}, SignDeps{Signer: &mockSigner{}})
		assertNoErr(t, err)
	})
	t.Run("empty in", func(t *testing.T) {
		_, err := Sign(context.Background(), SignRequest{PrivateKeyPath: "k.pem"}, SignDeps{Signer: &mockSigner{}})
		assertErr(t, err)
	})
	t.Run("empty key", func(t *testing.T) {
		_, err := Sign(context.Background(), SignRequest{InPath: "m.json"}, SignDeps{Signer: &mockSigner{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Sign(context.Background(), SignRequest{InPath: "m.json", PrivateKeyPath: "k.pem"}, SignDeps{Signer: &mockSigner{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Sign(canceled(), SignRequest{InPath: "m.json", PrivateKeyPath: "k.pem"}, SignDeps{Signer: &mockSigner{}})
		assertCanceled(t, err)
	})
}

func TestKeygen(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		_, err := Keygen(context.Background(), KeygenRequest{PrivateKeyPath: "a", PublicKeyPath: "b"}, KeygenDeps{Generator: &mockKeypairGen{}})
		assertNoErr(t, err)
	})
	t.Run("empty priv", func(t *testing.T) {
		_, err := Keygen(context.Background(), KeygenRequest{PublicKeyPath: "b"}, KeygenDeps{Generator: &mockKeypairGen{}})
		assertErr(t, err)
	})
	t.Run("empty pub", func(t *testing.T) {
		_, err := Keygen(context.Background(), KeygenRequest{PrivateKeyPath: "a"}, KeygenDeps{Generator: &mockKeypairGen{}})
		assertErr(t, err)
	})
	t.Run("error", func(t *testing.T) {
		_, err := Keygen(context.Background(), KeygenRequest{PrivateKeyPath: "a", PublicKeyPath: "b"}, KeygenDeps{Generator: &mockKeypairGen{err: errors.New("fail")}})
		assertErr(t, err)
	})
	t.Run("ctx", func(t *testing.T) {
		_, err := Keygen(canceled(), KeygenRequest{PrivateKeyPath: "a", PublicKeyPath: "b"}, KeygenDeps{Generator: &mockKeypairGen{}})
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
