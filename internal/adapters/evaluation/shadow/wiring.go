package shadow

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/sufield/stave/internal/adapters/evaluation/external"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/sir"
)

// EnvShadowCmd is the env var that enables shadow mode. Any
// non-empty value triggers wrapping; the actual command string
// is consumed by Iter 3.1.4's PythonSolverSource. Until then,
// any non-empty value substitutes a StubFindingSource secondary.
const EnvShadowCmd = "STAVE_SHADOW_CMD"

// EnvShadowTimeout overrides the default 30s secondary execution
// cap. Parsed as an integer number of seconds via strconv.Atoi
// so operators can tune without learning Go duration syntax;
// invalid values fall back to 30s with a debug log.
const EnvShadowTimeout = "STAVE_SHADOW_TIMEOUT"

// DefaultSecondaryTimeout is the timeout applied when
// STAVE_SHADOW_TIMEOUT is unset or unparseable.
const DefaultSecondaryTimeout = 30 * time.Second

// LogPrecomputedDivergence runs the secondary source and logs
// the divergence summary against the supplied primary findings,
// IF shadow mode is enabled (via STAVE_SHADOW_CMD).
//
// Iter 3.1.4: the secondary is now external.PythonSolverSource
// constructed from the parsed STAVE_SHADOW_CMD argv. The
// Iter 2.4 StubFindingSource is retired — every shadow run
// invokes the real solver.
//
// `req` carries the FindingRequest that produced the primary
// findings; the same request flows to the secondary so both
// engines reason over identical inputs. Caller (cmd/apply) is
// responsible for assembling it from the loaded controls /
// snapshots / now.
//
// When STAVE_SHADOW_CMD is unset the helper is a no-op — the
// shadow path imposes zero cost on operators who haven't opted
// in.
func LogPrecomputedDivergence(
	ctx context.Context,
	logger *slog.Logger,
	findings []evaluation.Finding,
	req evaluation.FindingRequest,
	builder *sir.Builder,
) {
	cmd := os.Getenv(EnvShadowCmd)
	if cmd == "" {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	timeout := resolveSecondaryTimeout(logger)

	invocation, err := external.ParseCommand(cmd)
	if err != nil || len(invocation.Argv) == 0 {
		logger.Warn("shadow: STAVE_SHADOW_CMD is set but did not parse to a usable argv",
			slog.String("raw", cmd),
			slog.Any("error", err),
		)
		return
	}

	primary := NewPrecomputedFindingSource(findings)
	secondary := external.NewPythonSolverSource(invocation, builder, timeout, logger)
	shadow := NewShadowFindingSource(primary, secondary, logger, timeout)
	// The precomputed primary returns the supplied findings
	// regardless of req; the secondary actually consumes the
	// request and produces solver output. We discard the
	// returned findings — the call's value is the divergence
	// log line emitted by the decorator. We DO surface the
	// returned error: a shadow-pipeline failure (subprocess
	// crash, malformed solver output) is operator-actionable
	// even though it must NOT block the primary path.
	if _, err := shadow.ProduceFindings(ctx, req); err != nil {
		logger.Warn("shadow: secondary solver failed; primary findings unaffected",
			slog.String("error", err.Error()))
	}
}

// resolveSecondaryTimeout reads STAVE_SHADOW_TIMEOUT and returns
// the duration to apply to secondary execution. Falls back to
// DefaultSecondaryTimeout on missing / unparseable input,
// logging the fallback at debug level so operators can spot a
// typo without it silently extending or shortening their cap.
func resolveSecondaryTimeout(logger *slog.Logger) time.Duration {
	raw := os.Getenv(EnvShadowTimeout)
	if raw == "" {
		return DefaultSecondaryTimeout
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		logger.Debug("shadow: invalid STAVE_SHADOW_TIMEOUT; using default",
			slog.String("raw", raw),
			slog.Duration("default", DefaultSecondaryTimeout),
		)
		return DefaultSecondaryTimeout
	}
	return time.Duration(n) * time.Second
}
