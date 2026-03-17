package contracts

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// LoadResult holds the output of a snapshot load: the parsed snapshots and
// their cryptographic hashes (nil when hashing is not applicable, e.g. stdin).
type LoadResult struct {
	Snapshots []asset.Snapshot
	Hashes    *evaluation.InputHashes
}

// ObservationRepository loads snapshots from storage.
type ObservationRepository interface {
	LoadSnapshots(ctx context.Context, dir string) (LoadResult, error)
}

// SnapshotReader loads a single snapshot from an io.Reader.
// This is the narrow port used by pruner (for timestamp extraction),
// stdin loading, and composition; ObservationRepository is the wider port.
type SnapshotReader interface {
	LoadSnapshotFromReader(ctx context.Context, r io.Reader, sourceName string) (asset.Snapshot, error)
}

// ControlRepository loads control definitions from storage.
type ControlRepository interface {
	LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error)
}

// LoadControls loads control definitions through the given repository,
// wrapping any error with a standard message.
func LoadControls(ctx context.Context, repo ControlRepository, dir string) ([]policy.ControlDefinition, error) {
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load controls: %w", err)
	}
	return controls, nil
}

// LoadSnapshots loads observation snapshots through the given repository,
// wrapping any error with a standard message.
func LoadSnapshots(ctx context.Context, repo ObservationRepository, dir string) (LoadResult, error) {
	result, err := repo.LoadSnapshots(ctx, dir)
	if err != nil {
		return LoadResult{}, fmt.Errorf("failed to load observations: %w", err)
	}
	return result, nil
}

// EnrichedResult holds evaluation output together with enriched findings
// and fully-sanitized metadata. Boundary type between the "enrich" and
// "marshal" pipeline steps. Marshalers should read ExemptedAssets and Run
// from this struct (not from Result) because they are pre-sanitized.
type EnrichedResult struct {
	Result         evaluation.Result
	Findings       []remediation.Finding
	ExemptedAssets []asset.ExemptedAsset
	Run            evaluation.RunInfo
}

// FindingMarshaler transforms enriched findings into format-specific bytes
// without performing I/O.
type FindingMarshaler interface {
	MarshalFindings(enriched EnrichedResult) ([]byte, error)
}

// EnrichFunc produces an EnrichedResult from an evaluation result.
// Implementations close over the enricher and sanitizer.
type EnrichFunc func(result evaluation.Result) EnrichedResult

// FileResultLoader loads an evaluation result from a file path.
type FileResultLoader interface {
	LoadFromFile(path string) (*evaluation.Result, error)
}

// ReaderResultLoader loads an evaluation result from an io.Reader.
type ReaderResultLoader interface {
	LoadFromReader(r io.Reader, sourceName string) (*evaluation.Result, error)
}

// ResultLoader combines file and reader loading into a single interface.
type ResultLoader interface {
	FileResultLoader
	ReaderResultLoader
}

// FileEnvelopeLoader loads a safety-envelope evaluation from a file path.
type FileEnvelopeLoader interface {
	LoadEnvelopeFromFile(path string) (*safetyenvelope.Evaluation, error)
}

// FileBaselineLoader loads an evaluation baseline from a file path.
type FileBaselineLoader interface {
	LoadBaselineFromFile(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error)
}

// IntegrityCheckConfigurer allows observation loaders to accept manifest
// verification configuration. Implementations must configure integrity
// checking before any snapshot listing calls.
type IntegrityCheckConfigurer interface {
	ConfigureIntegrityCheck(manifestPath, publicKeyPath string)
}

// ContentHasher computes reproducible digests over file system paths.
type ContentHasher interface {
	HashDir(path string, exts ...string) (string, error)
	HashFile(path string) (string, error)
}

// PackRegistry resolves built-in control packs from the embedded registry.
type PackRegistry interface {
	ResolveEnabledPacks(names []string) ([]string, error)
	RegistryVersion() (string, error)
	RegistryHash() (string, error)
}
