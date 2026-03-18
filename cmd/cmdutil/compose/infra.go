package compose

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/sync/errgroup"

	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	obsjson "github.com/sufield/stave/internal/adapters/input/observations/json"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/builtin/predicate"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

// Provider manages the instantiation of various adapters and repositories.
// It acts as a Service Locator/Factory registry.
type Provider struct {
	ObsRepoFunc       func() (appcontracts.ObservationRepository, error)
	StdinObsRepoFunc  func(io.Reader) (appcontracts.ObservationRepository, error)
	ControlRepoFunc   func() (appcontracts.ControlRepository, error)
	FindingWriterFunc func(format ui.OutputFormat, jsonMode bool) (appcontracts.FindingMarshaler, error)
}

// NewDefaultProvider returns a provider configured with standard adapters.
func NewDefaultProvider() *Provider {
	return &Provider{
		ObsRepoFunc: func() (appcontracts.ObservationRepository, error) {
			return obsjson.NewObservationLoader(), nil
		},
		StdinObsRepoFunc: func(r io.Reader) (appcontracts.ObservationRepository, error) {
			return obsjson.NewStdinObservationLoader(obsjson.NewObservationLoader(), r), nil
		},
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) {
			return ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.Resolve))
		},
		FindingWriterFunc: DefaultFindingWriter,
	}
}

// Compile-time check that ObservationLoader satisfies the composed snapshot interface.
var _ SnapshotObservationRepository = (*obsjson.ObservationLoader)(nil)

// SnapshotObservationRepository extends ObservationRepository with single-snapshot reader loading.
type SnapshotObservationRepository interface {
	appcontracts.ObservationRepository
	appcontracts.SnapshotReader
}

// --- Provider Repository Methods ---

// NewObservationRepo creates a new observation repository.
func (p *Provider) NewObservationRepo() (appcontracts.ObservationRepository, error) {
	return p.ObsRepoFunc()
}

// NewControlRepo creates a new control repository.
func (p *Provider) NewControlRepo() (appcontracts.ControlRepository, error) {
	return p.ControlRepoFunc()
}

// NewStdinObsRepo creates an observation repository that reads from stdin.
func (p *Provider) NewStdinObsRepo(r io.Reader) (appcontracts.ObservationRepository, error) {
	return p.StdinObsRepoFunc(r)
}

// NewSnapshotRepo creates a snapshot observation repository.
func (p *Provider) NewSnapshotRepo() (SnapshotObservationRepository, error) {
	repo, err := p.ObsRepoFunc()
	if err != nil {
		return nil, err
	}
	sr, ok := repo.(SnapshotObservationRepository)
	if !ok {
		return nil, fmt.Errorf("observation repository does not implement SnapshotReader")
	}
	return sr, nil
}

// NewFindingWriter creates a finding marshaler for the given output format.
func (p *Provider) NewFindingWriter(format ui.OutputFormat, jsonMode bool) (appcontracts.FindingMarshaler, error) {
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
