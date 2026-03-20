// Package json provides JSON-based loading functionality for observation snapshots.
// It handles parsing and validation of snapshot JSON files used in safety evaluations,
// using JSON Schema validation for contract enforcement.
package json

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/asset"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/integrity"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// ObservationValidator validates raw observation JSON against the contract schema.
type ObservationValidator interface {
	ValidateObservation(data []byte, source string) error
}

// contractObservationValidator adapts contractvalidator.Validator to ObservationValidator.
type contractObservationValidator struct {
	v *contractvalidator.Validator
}

func (c *contractObservationValidator) ValidateObservation(data []byte, source string) error {
	issues, err := c.v.ValidateObservationJSON(data, contractvalidator.WithPrefix(source))
	if err != nil {
		return fmt.Errorf("schema validation error: %w", err)
	}
	if issues.HasErrors() || issues.HasWarnings() {
		return fmt.Errorf("%w: %w", contractvalidator.ErrSchemaValidationFailed, issues)
	}
	return nil
}

// ObservationLoader loads snapshots from JSON files.
type ObservationLoader struct {
	validator              ObservationValidator
	integrityManifestPath  string
	integrityPublicKeyPath string
	// OnProgress is called after each file is processed with (processed, total) counts.
	// It is optional and safe to leave nil.
	OnProgress func(processed, total int)
}

var (
	_ appcontracts.ObservationRepository    = (*ObservationLoader)(nil)
	_ appcontracts.IntegrityCheckConfigurer = (*ObservationLoader)(nil)
)

// NewObservationLoader creates a new JSON observation loader with the default contract validator.
func NewObservationLoader() *ObservationLoader {
	return &ObservationLoader{
		validator: &contractObservationValidator{v: contractvalidator.New()},
	}
}

// LoadSnapshots loads all JSON snapshots from the given directory.
// It processes files in sorted order for deterministic loading and supports
// context cancellation for interruptible operations.
// The returned LoadResult includes SHA-256 hashes of each file for auditability.
func (l *ObservationLoader) LoadSnapshots(ctx context.Context, dir string) (appcontracts.LoadResult, error) {
	if err := ctx.Err(); err != nil {
		return appcontracts.LoadResult{}, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return appcontracts.LoadResult{}, fmt.Errorf("read observations: %w", err)
	}

	entries = filterJSONFiles(entries)
	slices.SortFunc(entries, func(a, b os.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})

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

		if l.OnProgress != nil {
			l.OnProgress(i+1, total)
		}
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

// SetOnProgress sets a callback that is called after each file is processed
// with (processed, total) counts. Pass nil to disable.
func (l *ObservationLoader) SetOnProgress(fn func(processed, total int)) {
	l.OnProgress = fn
}

// ConfigureIntegrityCheck sets optional manifest verification for future LoadSnapshots calls.
func (l *ObservationLoader) ConfigureIntegrityCheck(manifestPath, publicKeyPath string) {
	l.integrityManifestPath = manifestPath
	l.integrityPublicKeyPath = publicKeyPath
}

// filterJSONFiles returns only non-directory entries with a .json suffix.
func filterJSONFiles(entries []os.DirEntry) []os.DirEntry {
	return slices.DeleteFunc(entries, func(e os.DirEntry) bool {
		return e.IsDir() || !strings.HasSuffix(e.Name(), ".json")
	})
}

// process is the single processing pipeline: hash → validate → unmarshal.
func (l *ObservationLoader) process(data []byte, source string) (asset.Snapshot, string, error) {
	hash := string(platformcrypto.HashBytes(data))

	if err := l.validator.ValidateObservation(data, source); err != nil {
		return asset.Snapshot{}, "", err
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
