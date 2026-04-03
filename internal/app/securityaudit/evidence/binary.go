package evidence

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/outcome"
	"github.com/sufield/stave/internal/core/ports"
)

type binaryChecksumPayload struct {
	BinaryPath  string `json:"binary_path"`
	SHA256      string `json:"sha256"`
	GeneratedAt string `json:"generated_at"`
}

type binarySignaturePayload struct {
	ReleaseBundleDir string `json:"release_bundle_dir"`
	Verified         bool   `json:"verified"`
	Detail           string `json:"detail"`
	GeneratedAt      string `json:"generated_at"`
}

// releaseBundleParams bundles the data arguments for release bundle
// verification, preventing accidental swaps of the three string parameters.
type releaseBundleParams struct {
	BinaryPath       string
	ExpectedHash     string
	ReleaseBundleDir string
}

type DefaultBinaryInspector struct {
	SignatureVerifier ports.Verifier
	HashFile          func(path string) (kernel.Digest, error)
	ReadFile          func(path string) ([]byte, error)
	StatFile          func(string) (fs.FileInfo, error)
}

func (d DefaultBinaryInspector) Inspect(req Params, buildInfo BuildInfoSnapshot) (BinaryInspectionSnapshot, error) {
	path := strings.TrimSpace(req.BinaryPath)
	if path == "" {
		return BinaryInspectionSnapshot{}, fmt.Errorf("binary path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return BinaryInspectionSnapshot{}, fmt.Errorf("resolve binary path: %w", err)
	}

	hash, err := d.HashFile(abs)
	if err != nil {
		return BinaryInspectionSnapshot{}, fmt.Errorf("hash binary: %w", err)
	}

	checksumPayload := binaryChecksumPayload{
		BinaryPath:  abs,
		SHA256:      string(hash),
		GeneratedAt: req.Now.UTC().Format(time.RFC3339),
	}
	checksumJSON, err := json.MarshalIndent(checksumPayload, "", "  ")
	if err != nil {
		return BinaryInspectionSnapshot{}, fmt.Errorf("marshal binary checksum: %w", err)
	}

	signatureAttempt := strings.TrimSpace(req.ReleaseBundleDir) != ""
	signatureVerified := false
	signatureDetail := "release bundle not provided"
	var signatureJSON []byte

	if signatureAttempt {
		signatureVerified, signatureDetail = d.verifyReleaseBundle(releaseBundleParams{
			BinaryPath: abs, ExpectedHash: string(hash), ReleaseBundleDir: req.ReleaseBundleDir,
		})
		signaturePayload := binarySignaturePayload{
			ReleaseBundleDir: strings.TrimSpace(req.ReleaseBundleDir),
			Verified:         signatureVerified,
			Detail:           signatureDetail,
			GeneratedAt:      req.Now.UTC().Format(time.RFC3339),
		}
		var marshalErr error
		signatureJSON, marshalErr = json.MarshalIndent(signaturePayload, "", "  ")
		if marshalErr != nil {
			return BinaryInspectionSnapshot{}, fmt.Errorf("marshal signature payload: %w", marshalErr)
		}
		signatureJSON = append(signatureJSON, '\n')
	}

	hardeningStatus, hardeningDetail := evaluateBuildHardening(buildInfo)

	return BinaryInspectionSnapshot{
		BinaryPath:        abs,
		SHA256:            string(hash),
		ChecksumJSON:      append(checksumJSON, '\n'),
		SignatureJSON:     signatureJSON,
		SignatureAttempt:  signatureAttempt,
		SignatureVerified: signatureVerified,
		SignatureDetail:   signatureDetail,
		HardeningLevel:    hardeningStatus,
		HardeningDetail:   hardeningDetail,
	}, nil
}

func (d DefaultBinaryInspector) verifyReleaseBundle(params releaseBundleParams) (bool, string) {
	sumsPath := filepath.Join(params.ReleaseBundleDir, "SHA256SUMS")
	raw, err := d.ReadFile(sumsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read SHA256SUMS: %v", err)
	}

	if msg, ok := matchChecksumEntry(raw, filepath.Base(params.BinaryPath), params.ExpectedHash); !ok {
		return false, msg
	}

	return d.verifyChecksumSignature(raw, params.ReleaseBundleDir)
}

// matchChecksumEntry searches SHA256SUMS lines for the binary and verifies its hash.
// Uses a scanner to stream lines and exit early on match.
func matchChecksumEntry(raw []byte, binaryName, expectedHash string) (string, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		if name == binaryName {
			if strings.EqualFold(strings.TrimSpace(fields[0]), expectedHash) {
				return "", true
			}
			return "checksum mismatch between running binary and release bundle", false
		}
	}
	return fmt.Sprintf("binary %s not found in SHA256SUMS", binaryName), false
}

// verifyChecksumSignature validates the SHA256SUMS signature file.
func (d DefaultBinaryInspector) verifyChecksumSignature(sumsData []byte, bundleDir string) (bool, string) {
	sigBytes, sigErr := d.ReadFile(filepath.Join(bundleDir, "SHA256SUMS.sig"))
	if sigErr != nil {
		sigstorePath := filepath.Join(bundleDir, "SHA256SUMS.sigstore.json")
		if _, statErr := d.StatFile(sigstorePath); statErr == nil {
			return false, "checksum matched; sigstore bundle found but cryptographic verification of sigstore format is not yet supported"
		}
		return false, "checksum matched but no signature artifact found"
	}

	if d.SignatureVerifier == nil {
		return false, "checksum matched; signature file found but no signing public key configured for verification"
	}

	sig := kernel.Signature(strings.TrimSpace(string(sigBytes)))
	if verifyErr := d.SignatureVerifier.Verify(sumsData, sig); verifyErr != nil {
		return false, fmt.Sprintf("checksum matched but signature verification failed: %v", verifyErr)
	}
	return true, "checksum matched and signature cryptographically verified"
}

func evaluateBuildHardening(buildInfo BuildInfoSnapshot) (outcome.Status, string) {
	if len(buildInfo.Settings) == 0 {
		return outcome.Warn, "build settings unavailable; cannot verify hardening flags"
	}
	if strings.EqualFold(strings.TrimSpace(buildInfo.Settings["-buildmode"]), "pie") {
		return outcome.Pass, "buildmode=pie detected"
	}
	if goflags, ok := buildInfo.Settings["GOFLAGS"]; ok && strings.Contains(goflags, "-buildmode=pie") {
		return outcome.Pass, "GOFLAGS include -buildmode=pie"
	}
	return outcome.Warn, "PIE buildmode not detected in build settings"
}
