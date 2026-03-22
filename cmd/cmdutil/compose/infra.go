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
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// Provider manages the instantiation of various adapters and repositories.
// It acts as a Service Locator/Factory registry.
type Provider struct {
	ObsRepoFunc       func() (appcontracts.ObservationRepository, error)
	StdinObsRepoFunc  func(io.Reader) (appcontracts.ObservationRepository, error)
	ControlRepoFunc   func() (appcontracts.ControlRepository, error)
	FindingWriterFunc func(format ui.OutputFormat, jsonMode bool) (appcontracts.FindingMarshaler, error)
	CELEvalFunc       func() (policy.PredicateEval, error)
	SnapshotRepoFunc  func() (SnapshotObservationRepository, error)
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
		SnapshotRepoFunc: func() (SnapshotObservationRepository, error) {
			return observations.NewObservationLoader(), nil
		},
	}
}

// Compile-time check that ObservationLoader satisfies the composed snapshot interface.
var _ SnapshotObservationRepository = (*observations.ObservationLoader)(nil)

// SnapshotObservationRepository extends ObservationRepository with single-snapshot reader loading.
type SnapshotObservationRepository interface {
	appcontracts.ObservationRepository
	appcontracts.SnapshotReader
}

// --- Provider Repository Methods ---

// NewObservationRepo creates a new observation repository.
func (p *Provider) NewObservationRepo() (appcontracts.ObservationRepository, error) {
	if p.ObsRepoFunc == nil {
		return nil, fmt.Errorf("ObsRepoFunc not configured on Provider")
	}
	return p.ObsRepoFunc()
}

// NewControlRepo creates a new control repository.
func (p *Provider) NewControlRepo() (appcontracts.ControlRepository, error) {
	if p.ControlRepoFunc == nil {
		return nil, fmt.Errorf("ControlRepoFunc not configured on Provider")
	}
	return p.ControlRepoFunc()
}

// NewStdinObsRepo creates an observation repository that reads from stdin.
func (p *Provider) NewStdinObsRepo(r io.Reader) (appcontracts.ObservationRepository, error) {
	if p.StdinObsRepoFunc == nil {
		return nil, fmt.Errorf("StdinObsRepoFunc not configured on Provider")
	}
	return p.StdinObsRepoFunc(r)
}

// NewSnapshotRepo creates a snapshot observation repository.
// Requires SnapshotRepoFunc to be set (always true via NewDefaultProvider).
func (p *Provider) NewSnapshotRepo() (SnapshotObservationRepository, error) {
	if p.SnapshotRepoFunc == nil {
		return nil, fmt.Errorf("SnapshotRepoFunc not configured on Provider")
	}
	return p.SnapshotRepoFunc()
}

// NewFindingWriter creates a finding marshaler for the given output format.
func (p *Provider) NewFindingWriter(format ui.OutputFormat, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	if p.FindingWriterFunc == nil {
		return nil, fmt.Errorf("FindingWriterFunc not configured on Provider")
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
	obsRepo, err := p.ObsRepoFunc()
	if err != nil {
		return Assets{}, fmt.Errorf("create observation loader: %w", err)
	}
	ctlRepo, err := p.ControlRepoFunc()
	if err != nil {
		return Assets{}, fmt.Errorf("create control loader: %w", err)
	}

	var res Assets
	g, gCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		loadResult, loadErr := obsRepo.LoadSnapshots(gCtx, obsDir)
		if loadErr != nil {
			return fmt.Errorf("load observations from %q: %w", obsDir, loadErr)
		}
		res.Snapshots = loadResult.Snapshots
		return nil
	})

	g.Go(func() error {
		ctls, loadErr := ctlRepo.LoadControls(gCtx, ctlDir)
		if loadErr != nil {
			return fmt.Errorf("load controls from %q: %w", ctlDir, loadErr)
		}
		res.Controls = ctls
		return nil
	})

	if err := g.Wait(); err != nil {
		return Assets{}, err
	}
	return res, nil
}
