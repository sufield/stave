package app

import (
	"context"

	"github.com/sufield/stave/internal/core/asset"
	appcontracts "github.com/sufield/stave/internal/core/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

type evalControlRepoStub struct {
	controls []policy.ControlDefinition
	err      error
}

func (s evalControlRepoStub) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return s.controls, s.err
}

type evalObservationRepoStub struct {
	snapshots []asset.Snapshot
	err       error
	hashes    *evaluation.InputHashes
}

func (s evalObservationRepoStub) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{Snapshots: s.snapshots, Hashes: s.hashes}, s.err
}
