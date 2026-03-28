package evidence

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/securityaudit"
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
		signatureVerified, signatureDetail = verifyReleaseBundle(abs, string(hash), req.ReleaseBundleDir, d.SignatureVerifier, d.ReadFile, d.StatFile)
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

func verifyReleaseBundle(binaryPath string, expectedHash string, releaseBundleDir string, verifier ports.Verifier, readFile func(string) ([]byte, error), statFile func(string) (fs.FileInfo, error)) (bool, string) {
	sumsPath := filepath.Join(releaseBundleDir, "SHA256SUMS")
	raw, err := readFile(sumsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read SHA256SUMS: %v", err)
	}

	if msg, ok := matchChecksumEntry(raw, filepath.Base(binaryPath), expectedHash); !ok {
		return false, msg
	}

	return verifyChecksumSignature(raw, releaseBundleDir, verifier, readFile, statFile)
}

// matchChecksumEntry searches SHA256SUMS lines for the binary and verifies its hash.
func matchChecksumEntry(raw []byte, binaryName, expectedHash string) (string, bool) {
	for line := range strings.SplitSeq(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
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
func verifyChecksumSignature(sumsData []byte, releaseBundleDir string, verifier ports.Verifier, readFile func(string) ([]byte, error), statFile func(string) (fs.FileInfo, error)) (bool, string) {
	sigBytes, sigErr := readFile(filepath.Join(releaseBundleDir, "SHA256SUMS.sig"))
	if sigErr != nil {
		sigstorePath := filepath.Join(releaseBundleDir, "SHA256SUMS.sigstore.json")
		if _, statErr := statFile(sigstorePath); statErr == nil {
			return false, "checksum matched; sigstore bundle found but cryptographic verification of sigstore format is not yet supported"
		}
		return false, "checksum matched but no signature artifact found"
	}

	if verifier == nil {
		return false, "checksum matched; signature file found but no signing public key configured for verification"
	}

	sig := kernel.Signature(strings.TrimSpace(string(sigBytes)))
	if verifyErr := verifier.Verify(sumsData, sig); verifyErr != nil {
		return false, fmt.Sprintf("checksum matched but signature verification failed: %v", verifyErr)
	}
	return true, "checksum matched and signature cryptographically verified"
}

func evaluateBuildHardening(buildInfo BuildInfoSnapshot) (securityaudit.Status, string) {
	if len(buildInfo.Settings) == 0 {
		return securityaudit.StatusWarn, "build settings unavailable; cannot verify hardening flags"
	}
	if strings.EqualFold(strings.TrimSpace(buildInfo.Settings["-buildmode"]), "pie") {
		return securityaudit.StatusPass, "buildmode=pie detected"
	}
	if goflags, ok := buildInfo.Settings["GOFLAGS"]; ok && strings.Contains(goflags, "-buildmode=pie") {
		return securityaudit.StatusPass, "GOFLAGS include -buildmode=pie"
	}
	return securityaudit.StatusWarn, "PIE buildmode not detected in build settings"
}
