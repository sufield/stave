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

// Provider manages the instantiation of various adapters and repositories.
// It acts as a Service Locator/Factory registry.
type Provider struct {
	ObsRepoFunc       func() (appcontracts.ObservationRepository, error)
	StdinObsRepoFunc  func(io.Reader) (appcontracts.ObservationRepository, error)
	ControlRepoFunc   func() (appcontracts.ControlRepository, error)
	FindingWriterFunc func(format appcontracts.OutputFormat, jsonMode bool) (appcontracts.FindingMarshaler, error)
	CELEvalFunc       func() (policy.PredicateEval, error)
	SnapshotRepoFunc  func() (appcontracts.SnapshotReader, error)
}

// NewCELEvaluator returns the CEL predicate evaluator from the provider.
func (p *Provider) NewCELEvaluator() (policy.PredicateEval, error) {
	if p.CELEvalFunc != nil {
		return p.CELEvalFunc()
	}
	return stavecel.NewPredicateEval()
}

// NewDefaultProvider returns a provider configured with standard adapters.
func NewDefaultProvider() *Provider {
	return &Provider{
		ObsRepoFunc: func() (appcontracts.ObservationRepository, error) {
			return observations.NewObservationLoader(), nil
		},
		StdinObsRepoFunc: func(r io.Reader) (appcontracts.ObservationRepository, error) {
			return observations.NewStdinObservationLoader(observations.NewObservationLoader(), r), nil
		},
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) {
			return ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc()))
		},
		FindingWriterFunc: DefaultFindingWriter,
		CELEvalFunc:       stavecel.NewPredicateEval,
		SnapshotRepoFunc: func() (appcontracts.SnapshotReader, error) {
			return observations.NewObservationLoader(), nil
		},
	}
}

// Factory types for narrow dependency injection. Commands accept these
// instead of *Provider so their dependencies are explicit.
type (
	ObsRepoFactory       = func() (appcontracts.ObservationRepository, error)
	CtlRepoFactory       = func() (appcontracts.ControlRepository, error)
	SnapshotRepoFactory  = func() (appcontracts.SnapshotReader, error)
	CELEvaluatorFactory  = func() (policy.PredicateEval, error)
	FindingWriterFactory = func(appcontracts.OutputFormat, bool) (appcontracts.FindingMarshaler, error)
	SnapshotLoader       = func(ctx context.Context, dir string) ([]asset.Snapshot, error)
	AssetLoaderFunc      = func(ctx context.Context, obsDir, ctlDir string) (Assets, error)
)

// --- Provider Repository Methods ---

// NewObservationRepo creates a new observation repository.
func (p *Provider) NewObservationRepo() (appcontracts.ObservationRepository, error) {
	if p.ObsRepoFunc == nil {
		return nil, fmt.Errorf("obs repo func not configured on Provider")
	}
	return p.ObsRepoFunc()
}

// NewControlRepo creates a new control repository.
func (p *Provider) NewControlRepo() (appcontracts.ControlRepository, error) {
	if p.ControlRepoFunc == nil {
		return nil, fmt.Errorf("control repo func not configured on Provider")
	}
	return p.ControlRepoFunc()
}

// NewStdinObsRepo creates an observation repository that reads from stdin.
func (p *Provider) NewStdinObsRepo(r io.Reader) (appcontracts.ObservationRepository, error) {
	if p.StdinObsRepoFunc == nil {
		return nil, fmt.Errorf("stdin obs repo func not configured on Provider")
	}
	return p.StdinObsRepoFunc(r)
}

// NewSnapshotRepo creates a snapshot reader.
// Requires SnapshotRepoFunc to be set (always true via NewDefaultProvider).
func (p *Provider) NewSnapshotRepo() (appcontracts.SnapshotReader, error) {
	if p.SnapshotRepoFunc == nil {
		return nil, fmt.Errorf("snapshot repo func not configured on Provider")
	}
	return p.SnapshotRepoFunc()
}

// NewFindingWriter creates a finding marshaler for the given output format.
func (p *Provider) NewFindingWriter(format appcontracts.OutputFormat, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	if p.FindingWriterFunc == nil {
		return nil, fmt.Errorf("finding writer func not configured on Provider")
	}
	return p.FindingWriterFunc(format, jsonMode)
}

// --- Asset Loading ---

// Assets represents the data loaded for an evaluation.
type Assets struct {
	Snapshots []asset.Snapshot
	Controls  []policy.ControlDefinition
}

// LoadAssets concurrently fetches observations and controls.
func (p *Provider) LoadAssets(ctx context.Context, obsDir, ctlDir string) (Assets, error) {
	if p.ObsRepoFunc == nil {
		return Assets{}, fmt.Errorf("obs repo func not configured on Provider")
	}
	if p.ControlRepoFunc == nil {
		return Assets{}, fmt.Errorf("control repo func not configured on Provider")
	}
	obsRepo, err := p.ObsRepoFunc()
	if err != nil {
		return Assets{}, fmt.Errorf("create observation loader: %w", err)
	}
	ctlRepo, err := p.ControlRepoFunc()
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
