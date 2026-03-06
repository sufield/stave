package cmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestResolveNow_Empty(t *testing.T) {
	before := time.Now().UTC()
	got, err := cmdutil.ResolveNow("")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("resolveNow(\"\") = %v, want between %v and %v", got, before, after)
	}
}

func TestResolveNow_ValidRFC3339(t *testing.T) {
	got, err := cmdutil.ResolveNow("2026-01-15T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("resolveNow = %v, want %v", got, want)
	}
}

func TestResolveNow_NonUTC(t *testing.T) {
	got, err := cmdutil.ResolveNow("2026-01-15T12:00:00+05:00")
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
	_, err := cmdutil.ResolveNow("not-a-timestamp")
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}

// Mock implementations for testing LoadedAssets.Load.

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

func TestLoadedResourcesLoad_Success(t *testing.T) {
	snap := asset.Snapshot{CapturedAt: time.Now()}
	ctl := policy.ControlDefinition{ID: "TEST.001"}
	obs := &mockObsRepo{snapshots: []asset.Snapshot{snap}}
	ctlR := &mockCtlRepo{controls: []policy.ControlDefinition{ctl}}
	res := cmdutil.LoadedAssets{
		ObsRepo:     obs,
		ControlRepo: ctlR,
	}

	if err := res.Load(context.Background(), "obs", "ctl"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Snapshots) != 1 {
		t.Fatalf("got %d snapshots, want 1", len(res.Snapshots))
	}
	if len(res.Controls) != 1 {
		t.Fatalf("got %d controls, want 1", len(res.Controls))
	}
}

func TestLoadedResourcesLoad_ObsError(t *testing.T) {
	obs := &mockObsRepo{err: errors.New("obs boom")}
	ctlR := &mockCtlRepo{controls: []policy.ControlDefinition{{ID: "T"}}}
	res := cmdutil.LoadedAssets{
		ObsRepo:     obs,
		ControlRepo: ctlR,
	}

	err := res.Load(context.Background(), "obs", "ctl")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, obs.err) {
		t.Fatalf("expected wrapped obs error, got: %v", err)
	}
}

func TestLoadedResourcesLoad_InvError(t *testing.T) {
	obs := &mockObsRepo{snapshots: []asset.Snapshot{{}}}
	ctlR := &mockCtlRepo{err: errors.New("ctl boom")}
	res := cmdutil.LoadedAssets{
		ObsRepo:     obs,
		ControlRepo: ctlR,
	}

	err := res.Load(context.Background(), "obs", "ctl")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ctlR.err) {
		t.Fatalf("expected wrapped ctl error, got: %v", err)
	}
}
