package app

import (
	"context"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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
