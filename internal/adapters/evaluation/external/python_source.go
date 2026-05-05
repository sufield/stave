// Package external implements evaluation.FindingSource adapters
// that delegate to processes outside the Stave Go binary. The
// canonical use case is the Python Z3 solver under
// python/solver/, invoked as a subprocess via the command
// vector in STAVE_SHADOW_CMD.
//
// The solver communicates exclusively through stdin / stdout —
// no temp files, no shared memory, no Unix sockets — so the
// implementation is substitutable for any future solver that
// follows the same SIR-in / Findings-out contract.
package external

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/sir"
)

// SolverInvocation captures the full command vector to invoke
// the external solver, parsed once at construction time. argv[0]
// is the binary; the remaining elements are arguments. Parsing
// happens in ParseCommand below.
type SolverInvocation struct {
	Argv []string
}

// PythonSolverSource implements evaluation.FindingSource by
// shelling out to a SIR-consuming subprocess (typically the
// Python Z3 solver). It is the production replacement for the
// Iter 2.4 StubFindingSource — that stub is retired in this
// iteration.
//
// The builder is held by the source rather than passed per call
// because the SIR for a given (controls, snapshots, now) tuple
// is fixed; constructing one builder once and reusing it across
// shadow invocations matches the upstream pattern in
// cmd/exportsir/cmd.go.
type PythonSolverSource struct {
	invocation SolverInvocation
	builder    *sir.Builder
	timeout    time.Duration
	logger     *slog.Logger
}

// ErrSolverFailed is returned when the subprocess exits non-zero.
// The shadow source upstream catches this and treats it as a
// dark-launch divergence (logged, not propagated to the user).
var ErrSolverFailed = errors.New("python solver: subprocess failed")

// ErrSolverOutput is returned when the subprocess exits zero but
// stdout fails to unmarshal as []evaluation.Finding. The shadow
// upstream catches this the same way.
var ErrSolverOutput = errors.New("python solver: malformed output")

// ParseCommand splits a STAVE_SHADOW_CMD value into argv. Today
// the parser is simple whitespace-separated (strings.Fields):
// supports the common forms
//
//	python3 -m stave_solver.main
//	docker run --rm -i stave-solver:latest
//
// without pulling in a shellwords dependency. Arguments
// containing whitespace require pre-quoting at the
// invocation-vector level (e.g., wrap in a shell script that
// embeds the spaces); a future iteration can promote this to
// full POSIX tokenization if real workflows demand it.
//
// Empty input yields a nil argv and a nil error — callers gate
// on len(argv) > 0 to detect "no solver configured".
func ParseCommand(raw string) (SolverInvocation, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return SolverInvocation{}, nil
	}
	argv := strings.Fields(trimmed)
	if len(argv) == 0 {
		return SolverInvocation{}, nil
	}
	return SolverInvocation{Argv: argv}, nil
}

// NewPythonSolverSource constructs a source ready to invoke the
// configured subprocess. timeout caps each invocation; non-
// positive values default to 30s (matches the shadow wiring
// default in internal/adapters/evaluation/shadow). logger may
// be nil — falls back to slog.Default.
func NewPythonSolverSource(invocation SolverInvocation, builder *sir.Builder, timeout time.Duration, logger *slog.Logger) *PythonSolverSource {
	if logger == nil {
		logger = slog.Default()
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &PythonSolverSource{
		invocation: invocation,
		builder:    builder,
		timeout:    timeout,
		logger:     logger,
	}
}

// ProduceFindings satisfies evaluation.FindingSource.
//
// Pipeline:
//  1. Build the SIR document from the request via the configured
//     builder.
//  2. JSON-marshal the document.
//  3. exec.CommandContext the subprocess; pipe the SIR bytes to
//     stdin, capture stdout / stderr.
//  4. Apply timeout via context.WithTimeout.
//  5. Non-zero exit → ErrSolverFailed, with stderr at LevelWarn.
//  6. Unmarshal failure → ErrSolverOutput, with raw stdout
//     (truncated to 1KB) at LevelWarn.
//  7. Success → return the findings.
func (s *PythonSolverSource) ProduceFindings(ctx context.Context, req evaluation.FindingRequest) ([]evaluation.Finding, error) {
	if s == nil {
		return nil, errors.New("python solver: nil receiver")
	}
	if len(s.invocation.Argv) == 0 {
		return nil, errors.New("python solver: empty invocation argv")
	}
	if s.builder == nil {
		return nil, errors.New("python solver: nil SIR builder")
	}

	doc, err := s.builder.Build(req.Controls, req.Snapshots, req.Now)
	if err != nil {
		return nil, fmt.Errorf("python solver: build SIR: %w", err)
	}
	payload, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("python solver: marshal SIR: %w", err)
	}

	cmdCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, s.invocation.Argv[0], s.invocation.Argv[1:]...) //nolint:gosec // STAVE_SHADOW_CMD is operator-supplied; argv[0] is intentional
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		s.logger.Warn("python solver subprocess failed",
			slog.String("argv0", s.invocation.Argv[0]),
			slog.String("stderr", truncate(stderr.String(), 1024)),
			slog.Any("error", runErr),
		)
		return nil, fmt.Errorf("%w: %w", ErrSolverFailed, runErr)
	}

	var findings []evaluation.Finding
	if uerr := json.Unmarshal(stdout.Bytes(), &findings); uerr != nil {
		s.logger.Warn("python solver output failed to unmarshal",
			slog.String("stdout_truncated", truncate(stdout.String(), 1024)),
			slog.Any("error", uerr),
		)
		return nil, fmt.Errorf("%w: %w", ErrSolverOutput, uerr)
	}
	return findings, nil
}

// truncate caps a string at n bytes, appending "..." when
// truncated. Used for log-line-friendly diagnostics where the
// full subprocess output would otherwise dominate the log.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Compile-time assertion that the source satisfies the
// evaluation.FindingSource contract.
var _ evaluation.FindingSource = (*PythonSolverSource)(nil)

// Forward declarations to keep the imports honest — these
// types are referenced via the FindingRequest the contract
// passes through, but the adapter doesn't manipulate them
// directly.
var (
	_ = controldef.ControlDefinition{}
	_ = asset.Snapshot{}
)
