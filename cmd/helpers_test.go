package cmd

import (
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/runid"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/logging"
)

// getRootCmd returns a fully-wired root cobra command for tests.
// Tests assume wiring succeeds — a wiring failure aborts the test.
//
// The returned command is built fresh on each call. Callers that
// only inspect the command tree (help text, flag registrations,
// CLIG compliance walks) and do not mutate the command should
// prefer GetTestRootCmd() to avoid paying the wiring cost on every
// test in the package.
func getRootCmd() *cobra.Command {
	app, err := NewApp()
	if err != nil {
		panic("getRootCmd: " + err.Error())
	}
	return app.Root
}

// GetTestRootCmd returns a cached, fully-wired root cobra command
// for read-only tests. The instance is constructed once per
// process via sync.Once, then handed out to every caller.
//
// Reading-only contract: callers MUST treat the returned tree as
// immutable. Mutating it (adding subcommands, changing flags,
// running Execute) leaks state across tests and breaks any other
// test that touches the cached instance. Tests that need an
// isolated tree must use getRootCmd() instead.
//
// TestMain in this package can call resetTestRootCmdForBenchmark()
// when a benchmark needs to measure wiring cost; nothing in normal
// test runs needs to invalidate the cache.
func GetTestRootCmd() *cobra.Command {
	cachedTestRootCmdOnce.Do(func() {
		cachedTestRootCmd = getRootCmd()
	})
	return cachedTestRootCmd
}

var (
	cachedTestRootCmd     *cobra.Command
	cachedTestRootCmdOnce sync.Once
)

// getDevRootCmd returns a fully-wired root cobra command with all dev commands.
func getDevRootCmd() *cobra.Command {
	app, err := NewApp(WithDevEdition())
	if err != nil {
		panic("getDevRootCmd: " + err.Error())
	}
	return app.Root
}

// testAttachRunIDFromPlan attaches a run ID from the evaluation plan to the app logger.
func (a *App) testAttachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	if plan == nil {
		return
	}
	a.Logger = runid.SetupLoggingWithRunID(
		a.Logger,
		plan.ObservationsHash.String(),
		plan.ControlsHash.String(),
	)
	logging.SetDefaultLogger(a.Logger)
}

func TestResolveNow_Empty(t *testing.T) {
	before := time.Now().UTC()
	got, err := compose.ResolveEvalTime("")
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Before(before) || got.After(after) {
		t.Fatalf("resolveEvalTime(\"\") = %v, want between %v and %v", got, before, after)
	}
}

func TestResolveNow_ValidRFC3339(t *testing.T) {
	got, err := compose.ResolveEvalTime("2026-01-15T12:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("resolveEvalTime = %v, want %v", got, want)
	}
}

func TestResolveNow_NonUTC(t *testing.T) {
	got, err := compose.ResolveEvalTime("2026-01-15T12:00:00+05:00")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Location() != time.UTC {
		t.Fatalf("expected UTC, got %v", got.Location())
	}
	want := time.Date(2026, 1, 15, 7, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("resolveEvalTime = %v, want %v", got, want)
	}
}

func TestResolveNow_Invalid(t *testing.T) {
	_, err := compose.ResolveEvalTime("not-a-timestamp")
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
}
