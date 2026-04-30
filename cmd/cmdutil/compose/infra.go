package compose

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/sync/errgroup"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/builtin/predicate"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

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

// SnapshotLoader loads observation snapshots from a directory.
type SnapshotLoader = func(ctx context.Context, dir string) ([]asset.Snapshot, error)

// ControlLoaderFunc loads control definitions from a directory.
type ControlLoaderFunc = func(ctx context.Context, dir string) ([]policy.ControlDefinition, error)

// AssetLoaderFunc loads assets from observation and control directories.
type AssetLoaderFunc = func(ctx context.Context, obsDir, ctlDir string) (Assets, error)

// --- Factories (replaces Provider) ---

// Factories holds adapter constructor functions without methods.
// WireCommands destructures this into individual variables — no command
// ever receives the whole struct.
type Factories struct {
	NewObsRepo       ObsRepoFactory
	NewStdinObsRepo  func(io.Reader) (appcontracts.ObservationRepository, error)
	NewCtlRepo       CtlRepoFactory
	NewFindingWriter FindingWriterFactory
	NewCELEvaluator  CELEvaluatorFactory
	NewSnapshotRepo  SnapshotRepoFactory
}

// DefaultFactories returns factory functions configured with standard adapters.
func DefaultFactories() Factories {
	return Factories{
		NewObsRepo: func() (appcontracts.ObservationRepository, error) {
			return observations.NewObservationLoader(), nil
		},
		NewStdinObsRepo: func(r io.Reader) (appcontracts.ObservationRepository, error) {
			return observations.NewStdinObservationLoader(observations.NewObservationLoader(), r), nil
		},
		NewCtlRepo: func() (appcontracts.ControlRepository, error) {
			return ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc())), nil
		},
		NewFindingWriter: DefaultFindingWriter,
		NewCELEvaluator:  stavecel.NewPredicateEval,
		NewSnapshotRepo: func() (appcontracts.SnapshotReader, error) {
			return observations.NewObservationLoader(), nil
		},
	}
}

// --- Asset Loading ---

// Assets represents the data loaded for an evaluation.
type Assets struct {
	Snapshots []asset.Snapshot
	Controls  []policy.ControlDefinition
}

// LoadAssets concurrently fetches observations and controls using the
// provided factory functions.
func LoadAssets(ctx context.Context, newObs ObsRepoFactory, newCtl CtlRepoFactory, obsDir, ctlDir string) (Assets, error) {
	obsRepo, err := newObs()
	if err != nil {
		return Assets{}, fmt.Errorf("create observation loader: %w", err)
	}
	ctlRepo, err := newCtl()
	if err != nil {
		return Assets{}, fmt.Errorf("create control loader: %w", err)
	}

	var snapshots []asset.Snapshot
	var controls []policy.ControlDefinition

	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		loadResult, loadErr := obsRepo.LoadSnapshots(gCtx, obsDir)
		if loadErr != nil {
			return fmt.Errorf("load observations from %q: %w", obsDir, loadErr)
		}
		snapshots = loadResult.Snapshots
		return nil
	})

	g.Go(func() error {
		ctls, loadErr := ctlRepo.LoadControls(gCtx, ctlDir)
		if loadErr != nil {
			return fmt.Errorf("load controls from %q: %w", ctlDir, loadErr)
		}
		controls = ctls
		return nil
	})

	if err := g.Wait(); err != nil {
		return Assets{}, err
	}
	return Assets{Snapshots: snapshots, Controls: controls}, nil
}
