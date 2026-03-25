package crypto

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

var (
	// ErrNotPEM indicates the provided key material is not PEM encoded.
	ErrNotPEM = errors.New("data is not PEM encoded")
	// ErrInvalidKeyType indicates parsed key material is not Ed25519.
	ErrInvalidKeyType = errors.New("unsupported key type; Ed25519 required")
	// ErrInvalidSignature indicates signature verification failure.
	ErrInvalidSignature = errors.New("cryptographic signature invalid: manifest has been tampered with")
)

// verifier verifies Ed25519 signatures.
type verifier struct {
	publicKey ed25519.PublicKey
}

var _ ports.Verifier = (*verifier)(nil)

// NewVerifier returns a Verifier backed by the given Ed25519 public key.
// The key is validated at construction time so callers of Verify do not
// need to handle invalid-key errors.
func NewVerifier(pub ed25519.PublicKey) (ports.Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key length %d", ErrInvalidKeyType, len(pub))
	}
	return &verifier{publicKey: pub}, nil
}

// Verify validates an Ed25519 signature over data.
func (v *verifier) Verify(data []byte, sig kernel.Signature) error {
	if len(sig) == 0 {
		return fmt.Errorf("signature must be hex-encoded: empty signature")
	}

	decoded, err := hex.DecodeString(string(sig))
	if err != nil {
		return fmt.Errorf("signature must be hex-encoded: %w", err)
	}
	if len(decoded) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature length: expected %d, got %d", ed25519.SignatureSize, len(decoded))
	}
	if !ed25519.Verify(v.publicKey, data, decoded) {
		return ErrInvalidSignature
	}
	return nil
}

// ParsePublicKeyPEM parses a PEM-encoded Ed25519 public key.
func ParsePublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	block, err := decodePEM(data, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return publicKey, nil
}

// ParsePrivateKeyPEM parses a PEM-encoded private key and returns a Signer.
// The caller does not need to know the underlying algorithm.
func ParsePrivateKeyPEM(data []byte) (Signer, error) {
	block, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}
	edKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	return &ed25519Signer{key: edKey}, nil
}

// Signer produces cryptographic signatures. Implementations hide the
// algorithm so callers don't need to import crypto/ed25519.
type Signer interface {
	Sign(message []byte) (kernel.Signature, error)
}

// ed25519Signer wraps an Ed25519 private key behind the Signer interface.
type ed25519Signer struct {
	key ed25519.PrivateKey
}

func (s *ed25519Signer) Sign(message []byte) (kernel.Signature, error) {
	sig := ed25519.Sign(s.key, message)
	return kernel.Signature(hex.EncodeToString(sig)), nil
}

// GenerateSigningKeyPair generates a new Ed25519 keypair and returns
// the private and public keys as PEM-encoded bytes.
func GenerateSigningKeyPair() (privatePEM, publicPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate Ed25519 keypair: %w", err)
	}

	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	publicPKIX, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	privatePEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privatePKCS8})
	publicPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicPKIX})
	return privatePEM, publicPEM, nil
}

// decodePEM decodes PEM data and verifies the block type matches exactly.
func decodePEM(data []byte, expectedType string) (*pem.Block, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrNotPEM
	}
	if expectedType != "" && block.Type != expectedType {
		return nil, fmt.Errorf("%w: expected %s block, got %s", ErrInvalidKeyType, expectedType, block.Type)
	}
	return block, nil
}
