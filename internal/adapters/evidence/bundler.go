// Package evidence implements the portable evidence bundle for air-gap
// GRC integration. Produces a tar.gz containing assessment, logic trace,
// pruned snapshots, manifest, optional Ed25519 signature, and metadata.
package evidence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// BundleInput holds all data for building an evidence bundle.
type BundleInput struct {
	Assessment    *report.Assessment
	Snapshots     []asset.Snapshot
	TraceJSON     []byte // Pre-serialized logic trace
	PrivateKeyPEM []byte // Ed25519 private key PEM (nil = unsigned)
	StaveVersion  string
}

type manifestEntry struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	// int64 to match tar.Header.Size (which is int64). Using int
	// here would silently truncate file sizes above 2 GiB on 32-bit
	// platforms — the manifest would record a wrong length even
	// though the bundled file is intact.
	Size int64 `json:"size"`
}

type bundleManifest struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	OverallDigest string          `json:"overall_digest"`
	Files         []manifestEntry `json:"files"`
}

type bundleMetadata struct {
	SchemaVersion   string `json:"schema_version"`
	StaveVersion    string `json:"stave_version"`
	GeneratedAt     string `json:"generated_at"`
	AssetsEvaluated int    `json:"assets_evaluated"`
	FindingCount    int    `json:"findings"`
	ChainCount      int    `json:"chain_findings"`
	Signed          bool   `json:"signed"`
}

type bundleSignature struct {
	Algorithm   string `json:"algorithm"`
	Digest      string `json:"digest"`
	Signature   string `json:"signature"`
	PublicKeyID string `json:"public_key_id,omitempty"`
}

// Build creates a tar.gz evidence bundle from the given inputs.
func Build(input BundleInput) ([]byte, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Serialize assessment.
	assessmentJSON, err := json.MarshalIndent(input.Assessment, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal assessment: %w", err)
	}

	// Prune snapshots to violation-only assets.
	prunedJSON, err := marshalPrunedSnapshots(input.Snapshots, input.Assessment.Findings)
	if err != nil {
		return nil, fmt.Errorf("marshal pruned snapshots: %w", err)
	}

	// Build summary.
	summary := buildSummary(input)

	// Build metadata. AssetsEvaluated comes from the assessment's
	// TotalAssets — the number of distinct assets the engine evaluated,
	// not the number of controls. (The assessment doesn't carry a flat
	// "controls evaluated" count; per-framework counts live in
	// Summary.FrameworkReadiness if a framework was scoped.)
	metadata := bundleMetadata{
		SchemaVersion:   "evidence.v0.1",
		StaveVersion:    input.StaveVersion,
		GeneratedAt:     now,
		AssetsEvaluated: input.Assessment.Summary.TotalAssets,
		FindingCount:    input.Assessment.Summary.Violations,
		ChainCount:      len(input.Assessment.ChainFindings),
		Signed:          len(input.PrivateKeyPEM) > 0,
	}
	metadataJSON, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}

	// Collect all files for the bundle.
	files := map[string][]byte{
		"summary.txt":     summary,
		"assessment.json": assessmentJSON,
		"metadata.json":   metadataJSON,
	}
	if len(input.TraceJSON) > 0 {
		files["logic_trace.json"] = input.TraceJSON
	}
	if len(prunedJSON) > 0 {
		files["snapshots.json"] = prunedJSON
	}

	// Build manifest.
	manifest := buildManifest(files, now)
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	files["manifest.json"] = manifestJSON

	// Sign if private key provided.
	if len(input.PrivateKeyPEM) > 0 {
		sigJSON, signErr := signManifest(manifestJSON, input.PrivateKeyPEM)
		if signErr != nil {
			return nil, fmt.Errorf("sign manifest: %w", signErr)
		}
		files["signature.json"] = sigJSON
	}

	// Package as tar.gz.
	return writeTarGz(files)
}

func marshalPrunedSnapshots(snapshots []asset.Snapshot, findings []remediation.Finding) ([]byte, error) {
	violatedIDs := make(map[asset.ID]bool, len(findings))
	for i := range findings {
		violatedIDs[findings[i].AssetID] = true
	}

	var pruned []asset.Asset
	seen := make(map[asset.ID]bool)
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			if violatedIDs[a.ID] && !seen[a.ID] {
				pruned = append(pruned, a)
				seen[a.ID] = true
			}
		}
	}

	if len(pruned) == 0 {
		return nil, nil
	}
	return json.MarshalIndent(pruned, "", "  ")
}

func buildSummary(input BundleInput) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Stave Evidence Bundle\n")
	fmt.Fprintf(&buf, "=====================\n\n")
	fmt.Fprintf(&buf, "Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&buf, "Version:   %s\n", input.StaveVersion)
	fmt.Fprintf(&buf, "Status:    %s\n\n", input.Assessment.Status)
	fmt.Fprintf(&buf, "Assets evaluated:  %d\n", input.Assessment.Summary.TotalAssets)
	fmt.Fprintf(&buf, "Violations found:  %d\n", input.Assessment.Summary.Violations)
	fmt.Fprintf(&buf, "Chain findings:    %d\n", len(input.Assessment.ChainFindings))
	fmt.Fprintf(&buf, "Signed:            %v\n", len(input.PrivateKeyPEM) > 0)
	return buf.Bytes()
}

func buildManifest(files map[string][]byte, now string) bundleManifest {
	entries := make([]manifestEntry, 0, len(files))
	var hashes []string

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, name := range keys {
		data := files[name]
		sum := sha256.Sum256(data)
		h := hex.EncodeToString(sum[:])
		entries = append(entries, manifestEntry{
			File:   name,
			SHA256: h,
			Size:   int64(len(data)),
		})
		hashes = append(hashes, h)
	}

	overall := createCanonicalManifestDigest(hashes)

	return bundleManifest{
		SchemaVersion: "manifest.v0.1",
		GeneratedAt:   now,
		OverallDigest: "sha256:" + hex.EncodeToString(overall[:]),
		Files:         entries,
	}
}

// createCanonicalManifestDigest produces a stable SHA-256 of the
// per-file hashes that downstream verifiers can reproduce
// independent of Go version or internal slice formatting.
//
// The previous shape called fmt.Appendf("%v", hashes), which emits
// Go's default `[a b c]` slice syntax — not part of any spec we
// control, and a change to that formatter would drift the digest
// against archives produced by earlier Stave versions. A
// newline-joined list of hex hashes is the canonical form.
func createCanonicalManifestDigest(hashes []string) [32]byte {
	return sha256.Sum256([]byte(strings.Join(hashes, "\n")))
}

func signManifest(manifestJSON, privateKeyPEM []byte) ([]byte, error) {
	signer, err := platformcrypto.ParsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}

	digest := sha256.Sum256(manifestJSON)
	digestHex := hex.EncodeToString(digest[:])

	sig, err := signer.Sign(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	sigObj := bundleSignature{
		Algorithm: "ed25519",
		Digest:    "sha256:" + digestHex,
		Signature: string(sig),
	}
	return json.MarshalIndent(sigObj, "", "  ")
}

func writeTarGz(files map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Sort keys for deterministic archive.
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, name := range keys {
		data := files[name]
		hdr := &tar.Header{
			Name:    name,
			Size:    int64(len(data)),
			Mode:    0o644,
			ModTime: time.Now().UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("write tar data %s: %w", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip: %w", err)
	}
	return buf.Bytes(), nil
}
