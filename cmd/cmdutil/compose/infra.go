package compose

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/adapters/artifacts"
	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"
	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/adapters/sla"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// S3ResolverFactory creates an S3 permission resolver. Adapter
// concrete in production; test code can substitute an in-memory
// stub satisfying risk.PermissionResolver.
type S3ResolverFactory = func() risk.PermissionResolver

// ObsRepoFactory creates an observation repository for loading snapshots.
type ObsRepoFactory = func() (appcontracts.ObservationRepository, error)

// CtlRepoFactory creates a control repository for loading control definitions.
type CtlRepoFactory = func() (appcontracts.ControlRepository, error)

// SnapshotRepoFactory creates a snapshot reader for loading observations.
type SnapshotRepoFactory = func() (appcontracts.SnapshotReader, error)

// CELEvaluatorFactory creates a CEL predicate evaluator.
type CELEvaluatorFactory = func() (policy.PredicateEval, error)

// FindingWriterFactory creates a finding marshaler for the given output format.
type FindingWriterFactory = func(appcontracts.OutputFormat, bool) (appcontracts.FindingMarshaler, error)

// ChainLoaderFactory constructs a ChainDefinitionLoader for loading chain YAML.
type ChainLoaderFactory = func() (appcontracts.ChainDefinitionLoader, error)

// SLALoaderFactory constructs an SLAProvider for resolving SLA policies.
type SLALoaderFactory = func() (appcontracts.SLAProvider, error)

// ArtifactLoaderFactory constructs an ArtifactLoader for reading prior runs.
type ArtifactLoaderFactory = func() (appcontracts.ArtifactLoader, error)

// SnapshotBundleLoaderFactory constructs a SnapshotBundleLoader for
// loading multi-snapshot observation bundles from a single file.
type SnapshotBundleLoaderFactory = func() (appcontracts.SnapshotBundleLoader, error)

// BuiltinControlStoreFactory loads the embedded built-in control
// catalog. Returns the full set of control definitions in the
// embedded FS, suitable for catalog-level operations like
// validating compensating-control references. cmd/exempt's
// `validate` subcommand uses this to check that every
// compensating control mentioned in a user's acceptance file
// exists in the catalog.
type BuiltinControlStoreFactory = func() ([]policy.ControlDefinition, error)

// SnapshotLoader loads observation snapshots from a directory.
type SnapshotLoader = func(ctx context.Context, dir string) ([]asset.Snapshot, error)

// ControlLoaderFunc loads control definitions from a directory.
type ControlLoaderFunc = func(ctx context.Context, dir string) ([]policy.ControlDefinition, error)

// --- Factories (replaces Provider) ---

// Factories holds adapter constructor functions without methods.
// WireCommands destructures this into individual variables — no command
// ever receives the whole struct.
type Factories struct {
	NewObsRepo              ObsRepoFactory
	NewStdinObsRepo         func(io.Reader) (appcontracts.ObservationRepository, error)
	NewCtlRepo              CtlRepoFactory
	NewFindingWriter        FindingWriterFactory
	NewCELEvaluator         CELEvaluatorFactory
	NewSnapshotRepo         SnapshotRepoFactory
	NewChainLoader          ChainLoaderFactory
	NewSLALoader            SLALoaderFactory
	NewArtifactLoader       ArtifactLoaderFactory
	NewSnapshotBundleLoader SnapshotBundleLoaderFactory
	NewBuiltinControlStore  BuiltinControlStoreFactory
	NewS3Resolver           S3ResolverFactory
}

// BuiltinControlCatalog loads the embedded built-in control catalog
// with the standard alias resolver. It is the
// appcontracts.BuiltinControlLoader wired into the diagnose and
// validate application services for the "--controls absent" fallback,
// keeping the adapters/controls/builtin import inside the composition
// root rather than in internal/app/*.
func BuiltinControlCatalog() ([]policy.ControlDefinition, error) {
	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := store.All()
	if err != nil {
		return nil, fmt.Errorf("load builtin controls: %w", err)
	}
	return controls, nil
}

// DefaultFactories returns factory functions configured with standard adapters.
func DefaultFactories() Factories {
	return Factories{
		NewObsRepo: func() (appcontracts.ObservationRepository, error) {
			return observations.NewObservationLoader(), nil
		},
		NewStdinObsRepo: func(r io.Reader) (appcontracts.ObservationRepository, error) {
			return observations.NewStdinObservationLoader(observations.NewObservationLoader(), r)
		},
		NewCtlRepo: func() (appcontracts.ControlRepository, error) {
			return ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc())), nil
		},
		NewFindingWriter: DefaultFindingWriter,
		NewCELEvaluator:  stavecel.NewPredicateEval,
		NewSnapshotRepo: func() (appcontracts.SnapshotReader, error) {
			return observations.NewObservationLoader(), nil
		},
		NewChainLoader: func() (appcontracts.ChainDefinitionLoader, error) {
			return ctlyaml.NewChainProvider(), nil
		},
		NewSLALoader: func() (appcontracts.SLAProvider, error) {
			return sla.NewProvider(), nil
		},
		NewArtifactLoader: func() (appcontracts.ArtifactLoader, error) {
			return artifacts.NewLoader(), nil
		},
		NewSnapshotBundleLoader: func() (appcontracts.SnapshotBundleLoader, error) {
			return observations.NewBundleLoader(), nil
		},
		NewBuiltinControlStore: func() ([]policy.ControlDefinition, error) {
			store := ctlbuiltin.NewControlStore(
				controldata.FS,
				".",
				ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
			)
			return store.All()
		},
		NewS3Resolver: func() risk.PermissionResolver {
			return s3resolver.NewResolver()
		},
	}
}
