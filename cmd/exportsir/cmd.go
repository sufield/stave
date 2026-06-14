// Package exportsir implements the `stave export-sir` command,
// which materializes the Stave Intermediate Representation (SIR)
// for the configured controls + observations and emits it as
// JSON to stdout. The command is read-only and deterministic:
// the same controls, snapshots, and --now value produce
// byte-identical output.
//
// The SIR is the canonical, vendor-neutral fact set the future
// Z3 translator (Iteration 3) consumes. Today the command is
// the single observable proof that Iteration 1's hydration
// pipeline (role chains, exposure lifecycles, drift, S3
// effective permissions) flows end-to-end through the SIR
// builder and out as a stable JSON contract.
package exportsir

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
	"github.com/sufield/stave/pkg/stave/cliapi"
)

const (
	flagObservations = "observations"
	flagNow          = "now"
)

type options struct {
	ControlsDir     string
	ObservationsDir string
	Format          string
	Now             string
	Validate        bool
	AllowlistMode   string
	ClosedWorld     bool
	StripCatalog    bool
}

// NewCmd constructs the export-sir command. The command routes
// the evaluation + SIR build through cliapi.Apply — the same
// entry point cmd/apply uses — so there is one load path, one
// evaluation, and one SIR builder in the entire CLI. Output
// formatting (json | jsonl | smt2) is the only piece export-sir
// adds on top of what stave apply already does.
//
// No factory injection: cliapi.Apply owns the loaders. Tests
// drive the command by writing observation JSON to a tempdir
// and pointing --observations at it (same shape the CLI uses
// in production).
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "export-sir",
		Short: "Export the Stave Intermediate Representation as JSON",
		Long: `Export the Stave Intermediate Representation (SIR) for the configured
controls and observations as a deterministic document.

The SIR is the vendor-neutral fact set the Z3 solver consumes for compound
risk reasoning. It carries every control fact, asset, identity (with
transitive role chains), effective-permission edge, and exposure window
that the engine's evaluation pipeline produces — but stripped of
infrastructure noise (file paths, git metadata, tool versions).

Scope: the SIR is a curated projection, not a complete dump of every
property a control reads. The export currently covers 13 top-level
configuration domains (IAM, Cognito, S3 storage policies, Bedrock AI
agents, delegation, credential lifecycle, trail logging, network, and
a subset of compute / k8s). Properties in uncovered domains (Azure,
GCP, M365, databases, messaging, secrets, monitoring, and 80+ others)
are evaluated by CEL controls inside 'stave apply' but are NOT in the
export. A solver UNSAT verdict is valid for chains the SIR can express;
it is silent about chains whose members live in uncovered domains. See
the Fact Export reference in stave-guide for the full domain table.

Three output formats are supported:

  json    — full nested SIR document (default).
  jsonl   — one (subject, predicate, object) triple per line. Lossy
            projection optimised for Datalog/Soufflé and ASP/Clingo
            consumers that prefer flat predicate(s, o) facts.
  smt2    — SMT-LIB v2 declarations + assertions. The output contains
            facts only — no (check-sat), no queries — so any SMT solver
            (Z3, cvc5, Yices) reads the same file. Reasoning programs
            append their own query to the file before invoking the
            solver.

Inputs:
  --controls, -i      Control definitions directory (default: controls)
  --observations, -o  Observation snapshots directory (default: observations)
  --format, -f        Output format: json | jsonl | smt2 (default: json)
  --now               RFC3339 timestamp for deterministic output

Outputs:
  stdout: SIR document in the requested format.
  stderr: errors and progress (when stderr is a TTY).

Exit codes:
  0   success
  2   input error (bad flag, malformed --now)
  4   internal error (load failure, builder error)
  130 SIGINT
`,
		Example: `  # Export SIR for the project's default controls + observations
  stave export-sir > sir.json

  # Pin --now for byte-identical reproduction
  stave export-sir --now 2026-05-01T12:00:00Z > sir.json

  # Pretty-print for inspection
  stave export-sir | jq .

  # Triple form for Datalog / ASP consumers
  stave export-sir --format jsonl > facts.jsonl

  # SMT-LIB v2 facts; append a query before piping into z3 / cvc5
  stave export-sir --format smt2 > facts.smt2
  cat facts.smt2 query.smt2 | z3 -in`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.ControlsDir, cliflags.FlagControls, cliflags.FlagControlsShort, "controls", "control definitions directory")
	flags.StringVarP(&opts.ObservationsDir, flagObservations, "o", "observations", "observation snapshots directory")
	flags.StringVarP(&opts.Format, cliflags.FlagFormat, "f", "json", "output format: json | jsonl | smt2")
	flags.StringVar(&opts.Now, flagNow, "", "override current time (RFC3339) for deterministic output")
	flags.BoolVar(&opts.Validate, "validate", false,
		"check SIR coverage against CEL controls and warn on stderr about projection gaps "+
			"(controls that fire in CEL but evaluate properties not projected as SIR facts)")
	flags.StringVar(&opts.AllowlistMode, "allowlist-mode", "curated",
		"scalar projector mode: curated (default — 59 hand-authored entries) | "+
			"full (experimental — emit one auto_prop_<path> triple per control-read property "+
			"path the predicate index advertises; measures coverage gain, no downstream solver "+
			"consumes the auto_prop_* names yet)")
	flags.BoolVar(&opts.ClosedWorld, "closed-world", false,
		"emit closed-world forall axioms in SMT2 output (restricts each predicate to its "+
			"asserted tuples only; needed for negative proofs but causes solver timeout on "+
			"large fact sets)")
	flags.BoolVar(&opts.StripCatalog, "strip-catalog", false,
		"omit control catalog metadata (has_severity, has_type, has_domain) from the fact "+
			"stream; reduces SMT2/JSONL output to observation-derived facts only")

	return cmd
}

// run is the testable command body. UserError wraps input
// problems (mapped to exit code 2 by ui.ExitCode); plain errors
// fall through to exit code 4 (ExitInternal) — that's the
// convention the rest of the cmd/ tree follows.
//
// The body routes through cliapi.Apply — the same entry cmd/apply
// uses. One load, one CEL evaluator build, one SIR build, one
// fact extraction. export-sir adds output formatting (jsonl /
// smt2 / json) on top, nothing else.
func run(ctx context.Context, w io.Writer, errW io.Writer, opts *options) error {
	trimmed := strings.TrimSpace(opts.AllowlistMode)
	var allowlistMode string
	if trimmed == "" || strings.EqualFold(trimmed, "curated") {
		allowlistMode = "curated"
	} else if strings.EqualFold(trimmed, "full") {
		allowlistMode = "full"
	} else {
		return &ui.UserError{Err: fmt.Errorf("--allowlist-mode must be curated | full (got %q)", opts.AllowlistMode)}
	}

	now, err := resolveNow(opts.Now)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	// One load path: cliapi.ExportSIR routes through cliapi.Apply — the
	// loaders, the CEL evaluator, and the SIR builder — then projects facts
	// and renders. The validation report (--validate) comes back as stderr
	// bytes; no duplicate orchestration here.
	out, validationOut, err := cliapi.ExportSIR(ctx, cliapi.ExportSIRConfig{
		ControlsDir:     opts.ControlsDir,
		ObservationsDir: opts.ObservationsDir,
		Format: func() string {
			fmtTrimmed := strings.TrimSpace(opts.Format)
			if strings.EqualFold(fmtTrimmed, "jsonl") {
				return "jsonl"
			} else if strings.EqualFold(fmtTrimmed, "smt2") {
				return "smt2"
			} else if strings.EqualFold(fmtTrimmed, "json") {
				return "json"
			}
			return strings.ToLower(fmtTrimmed)
		}(),
		Now:           now,
		Validate:      opts.Validate,
		AllowlistMode: allowlistMode,
		ClosedWorld:   opts.ClosedWorld,
		StripCatalog:  opts.StripCatalog,
	})
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("evaluate"/"encode ..."); preserve exit 4.
	}

	if len(validationOut) > 0 {
		if _, werr := errW.Write(validationOut); werr != nil {
			return fmt.Errorf("write validation report: %w", werr)
		}
	}
	if _, werr := w.Write(out); werr != nil {
		return fmt.Errorf("write output: %w", werr)
	}
	return nil
}

// validateAndReport runs a lightweight evaluation pass against
// the loaded controls and snapshots to discover which controls
// fired, then compares each finding's predicate field paths
// against the SIR fact provenance for the same asset. The
// resolveNow returns the parsed --now value or, when --now is
// empty, the current wall-clock time. The empty case is the
// only place export-sir reads the wall clock; downstream
// determinism for fixture tests requires --now to be supplied.
func resolveNow(raw string) (time.Time, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("--now must be RFC3339 (got %q): %w", raw, err)
	}
	return t.UTC(), nil
}
