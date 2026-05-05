package shadow

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
)

// fakeReq + fakeBuilder give the wiring tests a builder that
// satisfies the signature without invoking any platform code.
// The dark-launch helper invokes builder.Build to produce SIR
// for the secondary; an empty document is fine for unit tests
// that only care about the divergence log line.
func fakeReq() evaluation.FindingRequest {
	return evaluation.FindingRequest{
		Now: time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
	}
}

func fakeBuilder() *sir.Builder { return sir.NewBuilder() }

func TestLogPrecomputedDivergence_NoEnvVarIsNoop(t *testing.T) {
	t.Setenv(EnvShadowCmd, "")

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	findings := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.X"), AssetID: asset.ID("a"), ControlSeverity: controldef.SeverityHigh},
	}
	LogPrecomputedDivergence(context.Background(), logger, findings, fakeReq(), fakeBuilder())

	if strings.Contains(buf.String(), "shadow") {
		t.Errorf("STAVE_SHADOW_CMD unset must produce no shadow log line; got %q", buf.String())
	}
}

// echoSolver: a tiny script that reads stdin (ignored) and
// prints "[]" to stdout. Substitutes for the real Python solver
// in unit tests so the wiring exercises the subprocess seam
// without depending on z3-solver being installed.
//
// The cmdline uses /bin/sh -c with a here-doc; resilient to
// whatever python interpreter is or isn't on PATH.
const echoSolverCmd = `/bin/sh -c cat>/dev/null;printf [] `

func TestLogPrecomputedDivergence_EnvVarSetEmitsLog(t *testing.T) {
	t.Setenv(EnvShadowCmd, echoSolverCmd)

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	findings := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.X"), AssetID: asset.ID("a"), ControlSeverity: controldef.SeverityHigh},
	}
	LogPrecomputedDivergence(context.Background(), logger, findings, fakeReq(), fakeBuilder())

	logged := buf.String()
	if !strings.Contains(logged, "shadow") {
		t.Errorf("STAVE_SHADOW_CMD set must produce shadow log line; got %q", logged)
	}
	// Echo solver returns []; primary has 1 finding → 1 missing.
	if !strings.Contains(logged, "diverge_missing=1") {
		t.Errorf("expected diverge_missing=1 (echo solver returns []), got %q", logged)
	}
}

func TestLogPrecomputedDivergence_TimeoutDefaultUsedOnInvalid(t *testing.T) {
	t.Setenv(EnvShadowCmd, echoSolverCmd)
	t.Setenv(EnvShadowTimeout, "not-a-number")

	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	LogPrecomputedDivergence(context.Background(), logger, nil, fakeReq(), fakeBuilder())

	logged := buf.String()
	if !strings.Contains(logged, "invalid STAVE_SHADOW_TIMEOUT") {
		t.Errorf("invalid timeout must log fallback note; got %q", logged)
	}
	if !strings.Contains(logged, "shadow") {
		t.Errorf("shadow log line still required; got %q", logged)
	}
}
