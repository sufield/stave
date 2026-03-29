package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestGenerateSigningKeyPair(t *testing.T) {
	privPEM, pubPEM, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair() error: %v", err)
	}

	if !strings.Contains(string(privPEM), "PRIVATE KEY") {
		t.Error("private key PEM missing PRIVATE KEY header")
	}
	if !strings.Contains(string(pubPEM), "PUBLIC KEY") {
		t.Error("public key PEM missing PUBLIC KEY header")
	}

	// Round-trip: parse and sign/verify
	signer, err := ParsePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM() error: %v", err)
	}

	pubKey, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM() error: %v", err)
	}

	msg := []byte("test-message")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error: %v", err)
	}

	v, err := NewVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewVerifier() error: %v", err)
	}
	if err := v.Verify(msg, sig); err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
}

func TestShortToken(t *testing.T) {
	tok := ShortToken("my-bucket")
	if len(tok) != 8 {
		t.Errorf("ShortToken length = %d, want 8", len(tok))
	}

	// Deterministic
	tok2 := ShortToken("my-bucket")
	if tok != tok2 {
		t.Errorf("ShortToken not deterministic: %q != %q", tok, tok2)
	}

	// Different inputs produce different tokens
	other := ShortToken("other-bucket")
	if tok == other {
		t.Error("different inputs produced same token")
	}

	// Verify correctness: first 4 bytes of SHA-256
	sum := sha256.Sum256([]byte("my-bucket"))
	want := hex.EncodeToString(sum[:4])
	if tok != want {
		t.Errorf("ShortToken = %q, want %q", tok, want)
	}
}

func TestStableID(t *testing.T) {
	id := StableID("FIX-", "some-input")
	if !strings.HasPrefix(id, "FIX-") {
		t.Errorf("StableID missing prefix, got %q", id)
	}

	// Prefix + 16 hex chars = prefix len + 16
	hexPart := strings.TrimPrefix(id, "FIX-")
	if len(hexPart) != 16 {
		t.Errorf("hex part length = %d, want 16", len(hexPart))
	}

	// Deterministic
	id2 := StableID("FIX-", "some-input")
	if id != id2 {
		t.Errorf("StableID not deterministic: %q != %q", id, id2)
	}

	// Different inputs produce different IDs
	other := StableID("FIX-", "other-input")
	if id == other {
		t.Error("different inputs produced same ID")
	}
}

func TestHashDelimited(t *testing.T) {
	parts := []string{"a", "b", "c"}
	d := HashDelimited(parts, '\n')
	if d == "" {
		t.Fatal("HashDelimited returned empty digest")
	}

	// Deterministic
	d2 := HashDelimited(parts, '\n')
	if d != d2 {
		t.Errorf("HashDelimited not deterministic: %q != %q", d, d2)
	}

	// Verify manually: "a\nb\nc\n" hashed
	h := sha256.New()
	h.Write([]byte("a\nb\nc\n"))
	want := kernel.Digest(hex.EncodeToString(h.Sum(nil)))
	if d != want {
		t.Errorf("HashDelimited = %q, want %q", d, want)
	}

	// Different separator
	d3 := HashDelimited(parts, '|')
	if d == d3 {
		t.Error("different separator should produce different digest")
	}

	// Empty parts
	empty := HashDelimited(nil, '\n')
	emptyHash := sha256.Sum256(nil)
	wantEmpty := kernel.Digest(hex.EncodeToString(emptyHash[:]))
	if empty != wantEmpty {
		t.Errorf("empty HashDelimited = %q, want %q", empty, wantEmpty)
	}
}

func TestNewHasher_Digest(t *testing.T) {
	h := NewHasher()
	d := h.Digest([]string{"x", "y"}, '\n')
	if d == "" {
		t.Fatal("Digest returned empty")
	}

	// Should match HashDelimited
	want := HashDelimited([]string{"x", "y"}, '\n')
	if d != want {
		t.Errorf("Digest = %q, want %q", d, want)
	}
}

func TestNewHasher_GenerateID(t *testing.T) {
	h := NewHasher()
	id := h.GenerateID("PRE-", "a", "b", "c")
	if !strings.HasPrefix(id, "PRE-") {
		t.Errorf("GenerateID missing prefix, got %q", id)
	}

	// Should match StableID with joined components
	want := StableID("PRE-", "a|b|c")
	if id != want {
		t.Errorf("GenerateID = %q, want %q", id, want)
	}
}
