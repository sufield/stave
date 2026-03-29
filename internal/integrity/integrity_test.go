package integrity

import (
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

func TestComputeOverall_Deterministic(t *testing.T) {
	files := map[evaluation.FilePath]kernel.Digest{
		"b.json": "sha256:bbb",
		"a.json": "sha256:aaa",
	}
	d1 := ComputeOverall(files)
	d2 := ComputeOverall(files)
	if d1 != d2 {
		t.Fatalf("ComputeOverall not deterministic: %q != %q", d1, d2)
	}
	if d1 == "" {
		t.Fatal("ComputeOverall returned empty digest")
	}
}

func TestComputeOverall_OrderIndependent(t *testing.T) {
	files1 := map[evaluation.FilePath]kernel.Digest{
		"a.json": "sha256:aaa",
		"b.json": "sha256:bbb",
	}
	files2 := map[evaluation.FilePath]kernel.Digest{
		"b.json": "sha256:bbb",
		"a.json": "sha256:aaa",
	}
	if ComputeOverall(files1) != ComputeOverall(files2) {
		t.Fatal("ComputeOverall should be order-independent")
	}
}

func TestComputeOverall_Empty(t *testing.T) {
	d := ComputeOverall(map[evaluation.FilePath]kernel.Digest{})
	if d == "" {
		t.Fatal("ComputeOverall(empty) returned empty digest")
	}
}

func TestManifest_ValidateOverall_Valid(t *testing.T) {
	files := map[evaluation.FilePath]kernel.Digest{
		"a.json": "sha256:aaa",
	}
	m := Manifest{
		Files:   files,
		Overall: ComputeOverall(files),
	}
	if err := m.ValidateOverall(); err != nil {
		t.Fatalf("ValidateOverall() error = %v", err)
	}
}

func TestManifest_ValidateOverall_Invalid(t *testing.T) {
	m := Manifest{
		Files:   map[evaluation.FilePath]kernel.Digest{"a.json": "sha256:aaa"},
		Overall: "sha256:wrong",
	}
	if err := m.ValidateOverall(); err == nil {
		t.Fatal("expected overall hash mismatch error")
	}
}

func TestManifest_CanonicalBytes_Deterministic(t *testing.T) {
	m := Manifest{
		Files: map[evaluation.FilePath]kernel.Digest{
			"b.json": "sha256:bbb",
			"a.json": "sha256:aaa",
		},
		Overall: "sha256:overall",
	}
	b1, err := m.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	b2, err := m.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatal("CanonicalBytes not deterministic")
	}
}

func TestValidator_Verify_Success(t *testing.T) {
	files := map[evaluation.FilePath]kernel.Digest{
		"a.json": "sha256:aaa",
		"b.json": "sha256:bbb",
	}
	overall := ComputeOverall(files)
	m := Manifest{Files: files, Overall: overall}

	v := &Validator{ActualHashes: &evaluation.InputHashes{
		Files:   files,
		Overall: overall,
	}}
	if err := v.Verify(m); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestValidator_Verify_NilHashes(t *testing.T) {
	v := &Validator{ActualHashes: nil}
	err := v.Verify(Manifest{})
	if err == nil || !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation, got %v", err)
	}
}

func TestValidator_Verify_MissingFile(t *testing.T) {
	m := Manifest{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": "sha256:aaa",
			"b.json": "sha256:bbb",
		},
	}
	v := &Validator{ActualHashes: &evaluation.InputHashes{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": "sha256:aaa",
		},
	}}
	err := v.Verify(m)
	if err == nil || !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation for missing file, got %v", err)
	}
}

func TestValidator_Verify_HashMismatch(t *testing.T) {
	m := Manifest{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": "sha256:aaa",
		},
	}
	v := &Validator{ActualHashes: &evaluation.InputHashes{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": "sha256:different",
		},
	}}
	err := v.Verify(m)
	if err == nil || !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation for hash mismatch, got %v", err)
	}
}

func TestValidator_Verify_ExtraFile(t *testing.T) {
	files := map[evaluation.FilePath]kernel.Digest{
		"a.json": "sha256:aaa",
	}
	overall := ComputeOverall(files)
	m := Manifest{Files: files, Overall: overall}

	v := &Validator{ActualHashes: &evaluation.InputHashes{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": "sha256:aaa",
			"c.json": "sha256:ccc",
		},
		Overall: overall,
	}}
	err := v.Verify(m)
	if err == nil || !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation for extra file, got %v", err)
	}
}

func TestValidator_Verify_OverallMismatch(t *testing.T) {
	files := map[evaluation.FilePath]kernel.Digest{
		"a.json": "sha256:aaa",
	}
	overall := ComputeOverall(files)
	m := Manifest{Files: files, Overall: overall}

	v := &Validator{ActualHashes: &evaluation.InputHashes{
		Files:   files,
		Overall: "sha256:wrong",
	}}
	err := v.Verify(m)
	if err == nil || !errors.Is(err, ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation for overall mismatch, got %v", err)
	}
}

type mockVerifier struct {
	err error
}

func (m *mockVerifier) Verify(_ []byte, _ kernel.Signature) error { return m.err }

func TestVerifySignedManifest_ValidSignature(t *testing.T) {
	m := Manifest{
		Files:   map[evaluation.FilePath]kernel.Digest{"a.json": "sha256:aaa"},
		Overall: "sha256:overall",
	}
	sm := SignedManifest{Manifest: m, Signature: "sig"}
	if err := VerifySignedManifest(sm, &mockVerifier{err: nil}); err != nil {
		t.Fatalf("VerifySignedManifest() error = %v", err)
	}
}

func TestVerifySignedManifest_InvalidSignature(t *testing.T) {
	m := Manifest{
		Files:   map[evaluation.FilePath]kernel.Digest{"a.json": "sha256:aaa"},
		Overall: "sha256:overall",
	}
	sm := SignedManifest{Manifest: m, Signature: "badsig"}
	err := VerifySignedManifest(sm, &mockVerifier{err: errors.New("bad sig")})
	if err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestUnmarshalSigned_InvalidJSON(t *testing.T) {
	_, err := UnmarshalSigned([]byte("{bad"), []byte("key"))
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

func TestUnmarshalSigned_InvalidPEM(t *testing.T) {
	validJSON := `{"manifest":{"files":{},"overall":"x"},"signature":"sig"}`
	_, err := UnmarshalSigned([]byte(validJSON), []byte("not-a-pem"))
	if err == nil {
		t.Fatal("expected PEM parse error")
	}
}

// Test with real Ed25519 key pair for end-to-end.
func TestSignedManifest_RoundTrip(t *testing.T) {
	privPEM, pubPEM, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	signer, err := crypto.ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	pub, err := crypto.ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	m := Manifest{
		Files:   map[evaluation.FilePath]kernel.Digest{"a.json": crypto.HashBytes([]byte("content"))},
		Overall: ComputeOverall(map[evaluation.FilePath]kernel.Digest{"a.json": crypto.HashBytes([]byte("content"))}),
	}
	canonical, err := m.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical bytes: %v", err)
	}
	sig, err := signer.Sign(canonical)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sm := SignedManifest{Manifest: m, Signature: sig}

	verifier, err := crypto.NewVerifier(pub)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := VerifySignedManifest(sm, verifier); err != nil {
		t.Fatalf("VerifySignedManifest roundtrip error = %v", err)
	}
}
