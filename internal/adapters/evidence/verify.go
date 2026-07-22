package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/kernel"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// VerifyResult holds the outcome of a bundle integrity check.
type VerifyResult struct {
	ManifestValid  bool
	SignatureValid bool
	Signed         bool
	FileCount      int
}

// Verify opens a .stave-bundle tar.gz and checks:
//  1. Every file listed in manifest.json has a matching SHA-256 digest.
//  2. If publicKeyPEM is non-nil and signature.json is present, the
//     Ed25519 signature over manifest.json is valid.
func Verify(bundleData, publicKeyPEM []byte) (VerifyResult, error) {
	files, err := extractTarGz(bundleData)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("extract bundle: %w", err)
	}

	manifestJSON, ok := files["manifest.json"]
	if !ok {
		return VerifyResult{}, errors.New("bundle missing manifest.json")
	}

	var manifest bundleManifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return VerifyResult{}, fmt.Errorf("parse manifest: %w", err)
	}

	for _, entry := range manifest.Files {
		data, exists := files[entry.File]
		if !exists {
			return VerifyResult{}, fmt.Errorf("manifest references missing file %q", entry.File)
		}
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if got != entry.SHA256 {
			return VerifyResult{ManifestValid: false, FileCount: len(manifest.Files)}, nil
		}
	}

	result := VerifyResult{
		ManifestValid: true,
		FileCount:     len(manifest.Files),
	}

	sigJSON, hasSig := files["signature.json"]
	result.Signed = hasSig

	if hasSig && len(publicKeyPEM) > 0 {
		pubKey, err := platformcrypto.ParsePublicKeyPEM(publicKeyPEM)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("parse public key: %w", err)
		}
		verifier, err := platformcrypto.NewVerifier(pubKey)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("create verifier: %w", err)
		}

		var sig bundleSignature
		if err := json.Unmarshal(sigJSON, &sig); err != nil {
			return VerifyResult{}, fmt.Errorf("parse signature: %w", err)
		}

		//nolint:nilerr // verification failure is a valid result, signalled by SignatureValid=false
		if err := verifier.Verify(manifestJSON, kernel.Signature(sig.Signature)); err != nil {
			result.SignatureValid = false
			return result, nil
		}
		result.SignatureValid = true
	}

	return result, nil
}

func extractTarGz(data []byte) (map[string][]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	files := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = content
	}

	return files, nil
}
