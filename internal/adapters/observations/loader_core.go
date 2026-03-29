// Package observations loads and validates observation snapshot files.
package observations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/integrity"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ObservationLoader loads snapshots from JSON files.
type ObservationLoader struct {
	validator              *contractvalidator.Validator
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
		return appcontracts.LoadResult{}, err
	}

	entries, err := listObservationFiles(dir)
	if err != nil {
		return appcontracts.LoadResult{}, err
	}

	var snapshots []asset.Snapshot
	fileHashes := make(map[string]string, len(entries))
	var joinedErr error
	total := len(entries)

	for i, entry := range entries {
		if err := ctx.Err(); err != nil {
			return appcontracts.LoadResult{}, err
		}

		path := filepath.Join(dir, entry.Name())
		data, err := fsutil.ReadFileLimited(path)
		if err != nil {
			joinedErr = errors.Join(joinedErr, fmt.Errorf("load snapshot %s: %w", path, err))
			continue
		}

		snap, hash, err := l.process(data, path)
		if err != nil {
			joinedErr = errors.Join(joinedErr, fmt.Errorf("load snapshot %s: %w", path, err))
			continue
		}
		snapshots = append(snapshots, snap)
		fileHashes[entry.Name()] = hash

		l.onProgress(i+1, total)
	}

	if joinedErr != nil {
		return appcontracts.LoadResult{}, joinedErr
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
	slices.SortFunc(entries, func(a, b os.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return entries, nil
}

// process is the single processing pipeline: hash → validate → unmarshal.
func (l *ObservationLoader) process(data []byte, source string) (asset.Snapshot, string, error) {
	hash := string(platformcrypto.HashBytes(data))

	issues, err := l.validator.ValidateObservationJSON(data, contractvalidator.WithPrefix(source))
	if err != nil {
		return asset.Snapshot{}, "", fmt.Errorf("schema validation error: %w", err)
	}
	if issues.HasErrors() || issues.HasWarnings() {
		return asset.Snapshot{}, "", fmt.Errorf("%w: %w", contractvalidator.ErrSchemaValidationFailed, issues)
	}

	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return asset.Snapshot{}, "", fmt.Errorf("unmarshal: %w", err)
	}
	if err := normalizeSnapshotTypes(&snap); err != nil {
		return asset.Snapshot{}, "", fmt.Errorf("invalid observation semantics: %w", err)
	}

	return snap, hash, nil
}

func buildInputHashes(fileHashes map[string]string) *evaluation.InputHashes {
	typedFiles := make(map[evaluation.FilePath]kernel.Digest, len(fileHashes))
	for name, hash := range fileHashes {
		typedFiles[evaluation.FilePath(name)] = kernel.Digest(hash)
	}
	return &evaluation.InputHashes{
		Files:   typedFiles,
		Overall: integrity.ComputeOverall(typedFiles),
	}
}
