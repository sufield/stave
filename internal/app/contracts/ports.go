package contracts

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
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
	Result         evaluation.Audit
	Findings       []EnrichedFinding
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
type EnrichFunc func(result evaluation.Audit) (EnrichedResult, error)

// ContentHasher computes reproducible digests over file system paths.
// Canonical definition lives in core/ports; this alias preserves backward
// compatibility for existing app-layer consumers.
type ContentHasher = ports.ContentHasher

// SnapshotFile represents a discovered snapshot file with its metadata.
// This type is defined in contracts (not in the adapter) so that both the app
// layer and the adapter layer can reference it without creating a dependency cycle.
type SnapshotFile struct {
	Path       string
	RelPath    string
	Name       string
	CapturedAt time.Time
}
