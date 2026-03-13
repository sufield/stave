package compose

import (
	"context"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// defaultProvider is the active provider used by package-level convenience
// functions. It is initialised with NewDefaultProvider() and can be replaced
// via UseProvider (at bootstrap) or OverrideProviderForTest (in tests).
var defaultProvider = NewDefaultProvider()

// UseProvider replaces the active provider used by the package-level
// convenience functions (NewObservationRepository, NewControlRepository, etc.).
// It is intended to be called once from App.bootstrap before any command runs.
//
// For test overrides that need automatic cleanup, use OverrideProviderForTest.
func UseProvider(p *Provider) {
	defaultProvider = p
}

// OverrideProviderForTest replaces the default provider for the duration of a test.
// The original provider is restored via t.Cleanup.
func OverrideProviderForTest(t interface {
	Helper()
	Cleanup(func())
}, p *Provider) {
	t.Helper()
	orig := defaultProvider
	defaultProvider = p
	t.Cleanup(func() { defaultProvider = orig })
}

// SnapshotObservationRepository extends ObservationRepository with single-snapshot reader loading.
type SnapshotObservationRepository interface {
	appcontracts.ObservationRepository
	appcontracts.SnapshotReader
}

// --- Package-level convenience functions ---

// NewObservationRepository creates a new observation repository.
func NewObservationRepository() (appcontracts.ObservationRepository, error) {
	return defaultProvider.ObsRepoFunc()
}

// NewControlRepository creates a new control repository.
func NewControlRepository() (appcontracts.ControlRepository, error) {
	return defaultProvider.ControlRepoFunc()
}

// NewStdinObservationRepository creates an observation repository that reads from stdin.
func NewStdinObservationRepository(r io.Reader) (appcontracts.ObservationRepository, error) {
	return defaultProvider.StdinObsRepoFunc(r)
}

// NewSnapshotObservationRepository creates a snapshot observation repository.
func NewSnapshotObservationRepository() (SnapshotObservationRepository, error) {
	repo, err := defaultProvider.ObsRepoFunc()
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
func NewFindingWriter(format string, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	return defaultProvider.FindingWriterFunc(format, jsonMode)
}

// LoadObsAndInv creates loaders and loads both concurrently.
func LoadObsAndInv(ctx context.Context, obsDir, ctlDir string) (Assets, error) {
	return defaultProvider.LoadAssets(ctx, obsDir, ctlDir)
}
