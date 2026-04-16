package attest

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snapshot.json")
	_ = os.WriteFile(snapPath, []byte(`{"test": true}`), 0o644)

	sig, err := Sign(snapPath, priv, "test-key", "2026-04-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteSig(snapPath, sig); err != nil {
		t.Fatal(err)
	}

	if err := Verify(snapPath, pub); err != nil {
		t.Fatalf("valid signature should verify: %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	pub, priv := testKeyPair(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snapshot.json")
	_ = os.WriteFile(snapPath, []byte(`{"test": true}`), 0o644)

	sig, _ := Sign(snapPath, priv, "test-key", "2026-04-01T00:00:00Z")
	_ = WriteSig(snapPath, sig)

	// Tamper with the snapshot.
	_ = os.WriteFile(snapPath, []byte(`{"tampered": true}`), 0o644)

	err := Verify(snapPath, pub)
	if err == nil {
		t.Fatal("tampered snapshot should fail verification")
	}
}

func TestVerify_MissingSig(t *testing.T) {
	pub, _ := testKeyPair(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snapshot.json")
	_ = os.WriteFile(snapPath, []byte(`{"test": true}`), 0o644)

	err := Verify(snapPath, pub)
	if err == nil {
		t.Fatal("missing .sig should fail")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv := testKeyPair(t)
	otherPub, _ := testKeyPair(t)
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "snapshot.json")
	_ = os.WriteFile(snapPath, []byte(`{"test": true}`), 0o644)

	sig, _ := Sign(snapPath, priv, "key-1", "2026-04-01T00:00:00Z")
	_ = WriteSig(snapPath, sig)

	err := Verify(snapPath, otherPub)
	if err == nil {
		t.Fatal("wrong key should fail verification")
	}
}
