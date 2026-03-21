package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestParsePublicKeyPEM(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubPKIX,
	})
	parsed, err := ParsePublicKeyPEM(pubPEM)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM() error = %v", err)
	}
	if string(parsed) != string(publicKey) {
		t.Fatalf("ParsePublicKeyPEM() mismatch")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privatePKCS8,
	})
	signer, err := ParsePrivateKeyPEM(privatePEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM() error = %v", err)
	}
	// Verify the signer produces valid signatures.
	msg := []byte("test message")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if sig == "" {
		t.Fatal("Sign() returned empty signature")
	}
}

func TestParsePublicKeyPEM_NotPEM(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "whitespace", data: []byte(" \n\t")},
		{name: "garbage", data: []byte("not-a-pem")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKeyPEM(tt.data)
			if !errors.Is(err, ErrNotPEM) {
				t.Fatalf("expected ErrNotPEM, got: %v", err)
			}
		})
	}
}

func TestParsePublicKeyPEM_WrongType(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPKIX, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal pub key: %v", err)
	}
	wrong := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pubPKIX,
	})

	_, err = ParsePublicKeyPEM(wrong)
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("expected ErrInvalidKeyType, got: %v", err)
	}
}

func TestParsePrivateKeyPEM_WrongType(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	wrong := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: privatePKCS8,
	})

	_, err = ParsePrivateKeyPEM(wrong)
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("expected ErrInvalidKeyType, got: %v", err)
	}
}

func TestVerifier_Verify(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	data := []byte("manifest")
	sig := kernel.Signature(hex.EncodeToString(ed25519.Sign(privateKey, data)))

	v := &Verifier{PublicKey: publicKey}
	if err := v.Verify(data, sig); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestVerifier_Verify_InvalidInputs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	data := []byte("manifest")
	goodSig := kernel.Signature(hex.EncodeToString(ed25519.Sign(privateKey, data)))

	tests := []struct {
		name      string
		verifier  *Verifier
		sig       kernel.Signature
		data      []byte
		wantIs    error
		wantInErr string
	}{
		{
			name:     "nil verifier",
			verifier: nil,
			sig:      goodSig,
			data:     data,
			wantIs:   ErrInvalidKeyType,
		},
		{
			name:     "invalid public key length",
			verifier: &Verifier{PublicKey: ed25519.PublicKey("short")},
			sig:      goodSig,
			data:     data,
			wantIs:   ErrInvalidKeyType,
		},
		{
			name:      "empty signature",
			verifier:  &Verifier{PublicKey: publicKey},
			sig:       kernel.Signature(" "),
			data:      data,
			wantInErr: "empty signature",
		},
		{
			name:      "non-hex signature",
			verifier:  &Verifier{PublicKey: publicKey},
			sig:       kernel.Signature("not-hex"),
			data:      data,
			wantInErr: "hex-encoded",
		},
		{
			name:      "wrong signature length",
			verifier:  &Verifier{PublicKey: publicKey},
			sig:       kernel.Signature("aa"),
			data:      data,
			wantInErr: "invalid signature length",
		},
		{
			name:     "invalid cryptographic signature",
			verifier: &Verifier{PublicKey: publicKey},
			sig:      goodSig,
			data:     []byte("tampered"),
			wantIs:   ErrInvalidSignature,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.Verify(tt.data, tt.sig)
			if err == nil {
				t.Fatal("expected verification error")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Fatalf("expected errors.Is(..., %v), got: %v", tt.wantIs, err)
			}
			if tt.wantInErr != "" && !strings.Contains(err.Error(), tt.wantInErr) {
				t.Fatalf("expected error containing %q, got: %v", tt.wantInErr, err)
			}
		})
	}
}

func TestSigner_RoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer := &ed25519Signer{key: privateKey}
	data := []byte("manifest")

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	raw, err := hex.DecodeString(string(sig))
	if err != nil {
		t.Fatalf("signature must be valid hex: %v", err)
	}
	if !ed25519.Verify(publicKey, data, raw) {
		t.Fatal("Signer.Sign() produced invalid signature")
	}
}
