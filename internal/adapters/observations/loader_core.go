// Package observations loads and validates observation snapshot files.
package observations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"

	"github.com/sufield/stave/internal/adapters/integrity"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ObservationLoader loads snapshots from JSON files.
type ObservationLoader struct {
	validator              contractvalidator.ObservationJSONValidator
	integrityManifestPath  string
	integrityPublicKeyPath string
	onProgress             func(processed, total int)
}

// LoaderOption configures an ObservationLoader.
type LoaderOption func(*ObservationLoader)

// WithOnProgress sets a callback invoked after each file is processed.
func WithOnProgress(fn func(processed, total int)) LoaderOption {
	return func(l *ObservationLoader) { l.onProgress = fn }
}

// WithIntegrityCheck enables manifest verification for loaded snapshots.
func WithIntegrityCheck(manifestPath, publicKeyPath string) LoaderOption {
	return func(l *ObservationLoader) {
		l.integrityManifestPath = manifestPath
		l.integrityPublicKeyPath = publicKeyPath
	}
}

var _ appcontracts.ObservationRepository = (*ObservationLoader)(nil)

// NewObservationLoader creates a new JSON observation loader with the default contract validator.
func NewObservationLoader(opts ...LoaderOption) *ObservationLoader {
	l := &ObservationLoader{
		validator:  contractvalidator.New(),
		onProgress: func(int, int) {},
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// LoadSnapshots loads all JSON snapshots from the given directory.
// It processes files in sorted order for deterministic loading and supports
// context cancellation for interruptible operations.
// The returned LoadResult includes SHA-256 hashes of each file for auditability.
func (l *ObservationLoader) LoadSnapshots(ctx context.Context, dir string) (appcontracts.LoadResult, error) {
	if err := ctx.Err(); err != nil {
		return appcontracts.LoadResult{}, fmt.Errorf("load snapshots: %w", err)
	}

	entries, err := listObservationFiles(dir)
	if err != nil {
		return appcontracts.LoadResult{}, err
	}

	var snapshots []asset.Snapshot
	fileHashes := make(map[string]string, len(entries))
	total := len(entries)

	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return appcontracts.LoadResult{}, fmt.Errorf("load snapshots: %w", err)
		}

		path := filepath.Join(dir, entry.Name())
		data, err := fsutil.ReadFileLimited(path)
		if err != nil {
			return appcontracts.LoadResult{}, fmt.Errorf("load snapshot %s: %w", path, err)
		}

		snaps, hash, err := l.process(data, path)
		if err != nil {
			return appcontracts.LoadResult{}, fmt.Errorf("load snapshot %s: %w", path, err)
		}
		snapshots = append(snapshots, snaps...)
		fileHashes[entry.Name()] = hash

		l.onProgress(i+1, total)
	}

	hashes := buildInputHashes(fileHashes)
	if err := l.verifyConfiguredIntegrity(hashes); err != nil {
		return appcontracts.LoadResult{}, err
	}

	return appcontracts.LoadResult{Snapshots: snapshots, Hashes: hashes}, nil
}

// listObservationFiles reads a directory and returns JSON file entries
// sorted by name for deterministic loading.
func listObservationFiles(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read observations: %w", err)
	}
	entries = slices.DeleteFunc(entries, func(e os.DirEntry) bool {
		return e.IsDir() || !strings.HasSuffix(e.Name(), ".json")
	})
	return entries, nil
}

// process is the single processing pipeline: detect shape →
// validate (single-file) or parse (bundle) → return snapshots + hash.
//
// Two accepted intake shapes:
//
//	{"schema_version":"obs.v0.1","captured_at":...,"assets":[...]}      // per-timestamp
//	{"schema_version":"obs.v0.1","snapshots":[{captured_at,assets},...]} // bundle
//
// Per-timestamp files run the full obs.v0.1 schema validator
// (additionalProperties: false rejects unexpected keys). Bundle
// files skip the per-file validator — bundle entries omit
// `schema_version` at the entry level so they would not pass the
// single-file schema by construction — and instead route through
// ParseBundle, which carries the bundle's own shape contract.
//
// The file-level hash is one entry per file regardless of how many
// snapshots a bundle expands to. The hash identifies the input
// artifact, not the snapshot count.
func (l *ObservationLoader) process(data []byte, source string) ([]asset.Snapshot, string, error) {
	hash := string(platformcrypto.HashBytes(data))

	if isBundleFormat(data) {
		snaps, err := ParseBundle(data)
		if err != nil {
			return nil, "", err
		}
		return snaps, hash, nil
	}

	issues, err := l.validator.ValidateObservationJSON(data, contractvalidator.WithPrefix(source))
	if err != nil {
		return nil, "", fmt.Errorf("schema validation error: %w", err)
	}
	if issues.Failed() {
		return nil, "", fmt.Errorf("%w: %w", contractvalidator.ErrSchemaValidationFailed, issues)
	}
	// Schema warnings are advisory: log them so the authoring
	// problem is visible without dropping the whole snapshot.
	// Mirrors the ControlLoader.loadOne pattern so observation and
	// control loading agree on what counts as fatal vs noisy.
	if issues.HasWarnings() {
		slog.Warn("observation schema validation warning",
			"source", source, "issues", issues.Error())
	}

	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, "", fmt.Errorf("unmarshal: %w", err)
	}
	if err := normalizeSnapshotTypes(&snap); err != nil {
		return nil, "", fmt.Errorf("invalid observation semantics: %w", err)
	}

	return []asset.Snapshot{snap}, hash, nil
}

// isBundleFormat reports whether data is the multi-snapshot bundle
// shape — i.e. a JSON object with a top-level `snapshots` array.
// Unmarshal into a probe struct rather than parsing the full document;
// cheap enough to run unconditionally on every loaded file. Returns
// false for malformed JSON so the per-file schema validator can emit
// the canonical parse-error message instead.
func isBundleFormat(data []byte) bool {
	var probe struct {
		Snapshots json.RawMessage `json:"snapshots"`
		Assets    json.RawMessage `json:"assets"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return len(probe.Snapshots) > 0 && !bytes.Equal(bytes.TrimSpace(probe.Snapshots), []byte("null")) && len(probe.Assets) == 0
}

func buildInputHashes(fileHashes map[string]string) *evaluation.InputHashes {
	// Walk fileHashes in sorted key order so the typedFiles map is
	// constructed deterministically. ComputeOverall already sorts
	// internally for hashing, but a deterministic build order
	// keeps any downstream consumer that reads the typed map
	// before re-hashing on the same iteration sequence (relevant
	// for trace logs that emit per-file hash lines during construction).
	names := make([]string, 0, len(fileHashes))
	for name := range fileHashes {
		names = append(names, name)
	}
	slices.Sort(names)

	typedFiles := make(map[evaluation.FilePath]kernel.Digest, len(fileHashes))
	for _, name := range names {
		typedFiles[evaluation.FilePath(name)] = kernel.Digest(fileHashes[name])
	}
	return &evaluation.InputHashes{
		Files:   typedFiles,
		Overall: integrity.ComputeOverall(typedFiles),
	}
}
