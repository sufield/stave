package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// getRootCmd returns a fully-wired root cobra command for tests.
func getRootCmd() *cobra.Command {
	return NewApp().Root
}

// getDevRootCmd returns a fully-wired root cobra command with all dev commands.
func getDevRootCmd() *cobra.Command {
	return NewApp(WithDevEdition()).Root
}

// testAttachRunIDFromPlan attaches a run ID from the evaluation plan to the app logger.
func (a *App) testAttachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	if plan == nil {
		return
	}
	a.Logger = cmdutil.SetupLoggingWithRunID(
		a.Logger,
		plan.ObservationsHash.String(),
		plan.ControlsHash.String(),
	)
	logging.SetDefaultLogger(a.Logger)
}

func TestResolveNow_Empty(t *testing.T) {
	before := time.Now().UTC()
	got, err := compose.ResolveNow("")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("resolveNow(\"\") = %v, want between %v and %v", got, before, after)
	}
}

func TestResolveNow_ValidRFC3339(t *testing.T) {
	got, err := compose.ResolveNow("2026-01-15T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("resolveNow = %v, want %v", got, want)
	}
}

func TestResolveNow_NonUTC(t *testing.T) {
	got, err := compose.ResolveNow("2026-01-15T12:00:00+05:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Location() != time.UTC {
		t.Fatalf("expected UTC, got %v", got.Location())
	}
	want := time.Date(2026, 1, 15, 7, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("resolveNow = %v, want %v", got, want)
	}
}

func TestResolveNow_Invalid(t *testing.T) {
	_, err := compose.ResolveNow("not-a-timestamp")
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

// Mock implementations for testing Provider.LoadAssets.

type mockObsRepo struct {
	snapshots []asset.Snapshot
	err       error
}

func (m *mockObsRepo) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{Snapshots: m.snapshots}, m.err
}

type mockCtlRepo struct {
	controls []policy.ControlDefinition
	err      error
}

func (m *mockCtlRepo) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return m.controls, m.err
}

func TestProviderLoadAssets_Success(t *testing.T) {
	snap := asset.Snapshot{CapturedAt: time.Now()}
	ctl := policy.ControlDefinition{ID: "TEST.001"}
	obs := &mockObsRepo{snapshots: []asset.Snapshot{snap}}
	ctlR := &mockCtlRepo{controls: []policy.ControlDefinition{ctl}}
	p := &compose.Provider{
		ObsRepoFunc:     func() (appcontracts.ObservationRepository, error) { return obs, nil },
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) { return ctlR, nil },
	}

	res, err := p.LoadAssets(context.Background(), "obs", "ctl")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Snapshots) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(res.Snapshots))
	}
	if len(res.Controls) != 1 {
		t.Fatalf("got %d controls, want 1", len(res.Controls))
	}
}

func TestProviderLoadAssets_ObsError(t *testing.T) {
	obsErr := errors.New("obs boom")
	obs := &mockObsRepo{err: obsErr}
	ctlR := &mockCtlRepo{controls: []policy.ControlDefinition{{ID: "T"}}}
	p := &compose.Provider{
		ObsRepoFunc:     func() (appcontracts.ObservationRepository, error) { return obs, nil },
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) { return ctlR, nil },
	}

	_, err := p.LoadAssets(context.Background(), "obs", "ctl")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, obsErr) {
		t.Fatalf("expected wrapped obs error, got: %v", err)
	}
}

func TestProviderLoadAssets_CtlError(t *testing.T) {
	ctlErr := errors.New("ctl boom")
	obs := &mockObsRepo{snapshots: []asset.Snapshot{{}}}
	ctlR := &mockCtlRepo{err: ctlErr}
	p := &compose.Provider{
		ObsRepoFunc:     func() (appcontracts.ObservationRepository, error) { return obs, nil },
		ControlRepoFunc: func() (appcontracts.ControlRepository, error) { return ctlR, nil },
	}

	_, err := p.LoadAssets(context.Background(), "obs", "ctl")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ctlErr) {
		t.Fatalf("expected wrapped ctl error, got: %v", err)
	}
}
