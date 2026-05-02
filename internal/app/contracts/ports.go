package contracts

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/report"
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

// EnrichedFinding pairs a raw evaluation finding with its remediation guidance.
// This is the port-boundary type used in EnrichedResult. It mirrors the
// fields of remediation.Finding without importing that core package, keeping
// the contracts layer free of business-logic dependencies.
type EnrichedFinding struct {
	evaluation.Finding
	RemediationSpec policy.RemediationSpec      `json:"remediation"`
	RemediationPlan *evaluation.RemediationPlan `json:"fix_plan,omitempty"`
}

// EnrichedResult holds evaluation output together with enriched findings
// and fully-sanitized metadata. Boundary type between the "enrich" and
// "marshal" pipeline steps. Marshalers should read ExemptedAssets and Run
// from this struct (not from Result) because they are pre-sanitized.
type EnrichedResult struct {
	Result          evaluation.ComplianceReport
	Findings        []EnrichedFinding
	ExemptedAssets  []asset.ExemptedAsset
	Run             evaluation.RunInfo
	CoveragePosture *coverage.CoverageIndex
}

// FindingMarshaler transforms enriched findings into format-specific bytes
// without performing I/O.
type FindingMarshaler interface {
	MarshalFindings(enriched *EnrichedResult) ([]byte, error)
}

// EnrichFunc produces an EnrichedResult from an evaluation result.
// Implementations close over the enricher and sanitizer.
type EnrichFunc func(result *evaluation.ComplianceReport) (EnrichedResult, error)

// ContentHasher computes reproducible digests over file system paths.
// Canonical definition lives in core/ports; this alias preserves backward
// compatibility for existing app-layer consumers.
type ContentHasher = ports.ContentHasher

// SnapshotFile represents a discovered snapshot file with its metadata.
// This type is defined in contracts (not in the adapter) so that both the app
// layer and the adapter layer can reference it without creating a dependency cycle.
//
// AssetID and AssetType are populated as best-effort: when the
// scanner runs with a SnapshotReader that successfully loads the
// observation, the first asset's ID and type are recorded for use
// in the plan / inventory contracts. When no loader is available
// (default modification-time scan) the fields are empty strings.
type SnapshotFile struct {
	Path       string
	RelPath    string
	Name       string
	CapturedAt time.Time
	AssetID    string
	AssetType  string
}

// SnapshotBundleLoader loads a multi-snapshot observation bundle from a single file.
// Used by ranking when an `--identity` snapshot is supplied directly. Distinct from
// ObservationRepository (directory of single-snapshot files); a bundle is one file
// holding many snapshots and skips the per-file schema validation pass.
type SnapshotBundleLoader interface {
	LoadBundle(ctx context.Context, path string) ([]asset.Snapshot, error)
}

// ChainDefinitionLoader loads chain definitions from a directory.
// A nil capability registry skips capability validation; structural validation
// always runs.
type ChainDefinitionLoader interface {
	LoadChains(ctx context.Context, dir string, registry policy.CapabilityRegistry) ([]policy.ChainDefinition, error)
}

// SLAProvider resolves an SLA policy from either a file path or an embedded
// profile name. Implementations apply the file-takes-precedence rule when
// both are non-empty. Returns a nil *evaluation.SLAConfig when both inputs
// are empty (no SLA configured).
type SLAProvider interface {
	LoadSLAConfig(ctx context.Context, profileID, filePath string) (*evaluation.SLAConfig, error)
}

// ArtifactLoader loads previously persisted Stave artifacts (assessment
// envelopes) from filesystem paths. Used by report, score, monitor, trend,
// and gate commands to read prior runs. The method name matches the
// existing *artifacts.Loader concrete adapter to minimize call-site churn.
type ArtifactLoader interface {
	Evaluation(ctx context.Context, path string) (*report.Assessment, error)
}
