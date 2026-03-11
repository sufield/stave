package securityaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/domain/securityaudit"
)

type defaultBinaryInspector struct {
	signatureVerifier ports.Verifier
	hashFile          func(path string) (kernel.Digest, error)
	readFile          func(path string) ([]byte, error)
}

func (d defaultBinaryInspector) Inspect(req SecurityAuditRequest, buildInfo buildInfoSnapshot) (binaryInspectionSnapshot, error) {
	path := strings.TrimSpace(req.BinaryPath)
	if path == "" {
		return binaryInspectionSnapshot{}, fmt.Errorf("binary path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return binaryInspectionSnapshot{}, fmt.Errorf("resolve binary path: %w", err)
	}

	hash, err := d.hashFile(abs)
	if err != nil {
		return binaryInspectionSnapshot{}, fmt.Errorf("hash binary: %w", err)
	}

	checksumPayload := map[string]any{
		"binary_path":  abs,
		"sha256":       hash,
		"generated_at": req.Now.UTC().Format(time.RFC3339),
	}
	checksumJSON, err := json.MarshalIndent(checksumPayload, "", "  ")
	if err != nil {
		return binaryInspectionSnapshot{}, fmt.Errorf("marshal binary checksum: %w", err)
	}

	signatureAttempt := strings.TrimSpace(req.ReleaseBundleDir) != ""
	signatureVerified := false
	signatureDetail := "release bundle not provided"
	var signatureJSON []byte

	if signatureAttempt {
		signatureVerified, signatureDetail = verifyReleaseBundle(abs, string(hash), req.ReleaseBundleDir, d.signatureVerifier, d.readFile)
		signaturePayload := map[string]any{
			"release_bundle_dir": strings.TrimSpace(req.ReleaseBundleDir),
			"verified":           signatureVerified,
			"detail":             signatureDetail,
			"generated_at":       req.Now.UTC().Format(time.RFC3339),
		}
		signatureJSON, _ = json.MarshalIndent(signaturePayload, "", "  ")
		if len(signatureJSON) > 0 {
			signatureJSON = append(signatureJSON, '\n')
		}
	}

	hardeningStatus, hardeningDetail := evaluateBuildHardening(buildInfo)

	return binaryInspectionSnapshot{
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

func verifyReleaseBundle(binaryPath string, expectedHash string, releaseBundleDir string, verifier ports.Verifier, readFile func(string) ([]byte, error)) (bool, string) {
	sumsPath := filepath.Join(releaseBundleDir, "SHA256SUMS")
	raw, err := readFile(sumsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read SHA256SUMS: %v", err)
	}

	if msg, ok := matchChecksumEntry(raw, filepath.Base(binaryPath), expectedHash); !ok {
		return false, msg
	}

	return verifyChecksumSignature(raw, releaseBundleDir, verifier, readFile)
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
func verifyChecksumSignature(sumsData []byte, releaseBundleDir string, verifier ports.Verifier, readFile func(string) ([]byte, error)) (bool, string) {
	sigBytes, sigErr := readFile(filepath.Join(releaseBundleDir, "SHA256SUMS.sig"))
	if sigErr != nil {
		sigstorePath := filepath.Join(releaseBundleDir, "SHA256SUMS.sigstore.json")
		if _, statErr := os.Stat(sigstorePath); statErr == nil {
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

func evaluateBuildHardening(buildInfo buildInfoSnapshot) (securityaudit.Status, string) {
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
