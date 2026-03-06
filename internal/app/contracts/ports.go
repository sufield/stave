package contracts

import (
	"context"
	"io"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/policy"
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

// ControlRepository loads control definitions from storage.
type ControlRepository interface {
	LoadControls(ctx context.Context, dir string) ([]policy.ControlDefinition, error)
}

// FindingWriter outputs findings in a specific format.
type FindingWriter interface {
	WriteFindings(w io.Writer, result evaluation.Result) error
}

// EnrichedResult holds evaluation output together with enriched findings
// and fully-sanitized metadata. Boundary type between the "enrich" and
// "marshal" pipeline steps. Marshalers should read SkippedAssets and Run
// from this struct (not from Result) because they are pre-sanitized.
type EnrichedResult struct {
	Result        evaluation.Result
	Findings      []remediation.Finding
	SkippedAssets []asset.SkippedAsset
	Run           evaluation.RunInfo
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

// IntegrityCheckConfigurer allows observation loaders to accept manifest
// verification configuration. Implementations must configure integrity
// checking before any snapshot listing calls.
type IntegrityCheckConfigurer interface {
	ConfigureIntegrityCheck(manifestPath, publicKeyPath string)
}
