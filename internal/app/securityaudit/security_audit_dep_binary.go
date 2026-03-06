package securityaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/securityaudit"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type defaultBinaryInspector struct{}

func (defaultBinaryInspector) Inspect(req SecurityAuditRequest, buildInfo buildInfoSnapshot) (binaryInspectionSnapshot, error) {
	path := strings.TrimSpace(req.BinaryPath)
	if path == "" {
		return binaryInspectionSnapshot{}, fmt.Errorf("binary path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return binaryInspectionSnapshot{}, fmt.Errorf("resolve binary path: %w", err)
	}

	hash, err := fsutil.HashFile(abs)
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
		signatureVerified, signatureDetail = verifyReleaseBundle(abs, string(hash), req.ReleaseBundleDir)
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

func verifyReleaseBundle(binaryPath string, expectedHash string, releaseBundleDir string) (bool, string) {
	sumsPath := filepath.Join(releaseBundleDir, "SHA256SUMS")
	raw, err := fsutil.ReadFileLimited(sumsPath)
	if err != nil {
		return false, fmt.Sprintf("cannot read SHA256SUMS: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	base := filepath.Base(binaryPath)

	hashMatch := false
	entryFound := false
	for _, line := range lines {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		hashValue := strings.TrimSpace(fields[0])
		name := strings.TrimPrefix(strings.TrimSpace(fields[1]), "*")
		if name == base {
			entryFound = true
			if strings.EqualFold(hashValue, expectedHash) {
				hashMatch = true
				break
			}
		}
	}

	if !entryFound {
		return false, fmt.Sprintf("binary %s not found in SHA256SUMS", base)
	}
	if !hashMatch {
		return false, "checksum mismatch between running binary and release bundle"
	}

	sigstorePath := filepath.Join(releaseBundleDir, "SHA256SUMS.sigstore.json")
	signaturePath := filepath.Join(releaseBundleDir, "SHA256SUMS.sig")
	if _, sigErr := os.Stat(sigstorePath); sigErr == nil {
		return true, "checksum matched and sigstore bundle present"
	}
	if _, sigErr := os.Stat(signaturePath); sigErr == nil {
		return true, "checksum matched and detached signature file present"
	}
	return false, "checksum matched but no signature artifact found"
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
