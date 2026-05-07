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
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/sirbridge"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/sir"
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
}

// NewCmd constructs the export-sir command. Dependencies are
// injected as factories (matching the rest of the cmd/ tree) so
// tests can substitute in-memory repositories without spinning
// up the full CLI bootstrap.
func NewCmd(newCtlRepo compose.CtlRepoFactory, newObsRepo compose.ObsRepoFactory, newCELEvaluator compose.CELEvaluatorFactory) *cobra.Command {
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
			return run(cmd.Context(), cmd.OutOrStdout(), opts, newCtlRepo, newObsRepo, newCELEvaluator)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.ControlsDir, cliflags.FlagControls, cliflags.FlagControlsShort, "controls", "control definitions directory")
	flags.StringVarP(&opts.ObservationsDir, flagObservations, "o", "observations", "observation snapshots directory")
	flags.StringVarP(&opts.Format, cliflags.FlagFormat, "f", "json", "output format: json | jsonl | smt2")
	flags.StringVar(&opts.Now, flagNow, "", "override current time (RFC3339) for deterministic output")

	return cmd
}

// run is the testable command body. UserError wraps input
// problems (mapped to exit code 2 by ui.ExitCode); plain errors
// fall through to exit code 4 (ExitInternal) — that's the
// convention the rest of the cmd/ tree follows.
func run(ctx context.Context, w io.Writer, opts *options, newCtlRepo compose.CtlRepoFactory, newObsRepo compose.ObsRepoFactory, newCELEvaluator compose.CELEvaluatorFactory) error {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	switch format {
	case "", "json", "jsonl", "smt2":
		// supported
	default:
		return &ui.UserError{Err: fmt.Errorf("--format must be one of json | jsonl | smt2 (got %q)", opts.Format)}
	}

	now, err := resolveNow(opts.Now)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	controls, err := compose.LoadControlsFrom(ctx, newCtlRepo, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	snapshots, err := compose.LoadSnapshotsFrom(ctx, newObsRepo, opts.ObservationsDir)
	if err != nil {
		return fmt.Errorf("load observations: %w", err)
	}

	celEval, err := newCELEvaluator()
	if err != nil {
		return fmt.Errorf("build CEL evaluator: %w", err)
	}

	builder := sir.NewBuilder(
		sir.WithRoleChainSource(sirbridge.NewAWSRoleChainSource()),
		sir.WithLifecycleSource(sirbridge.NewEngineLifecycleSource(celEval)),
		sir.WithResourceFactGrouper(sirbridge.NewAWSS3FactGrouper()),
	)

	doc, err := builder.Build(controls, snapshots, now)
	if err != nil {
		return fmt.Errorf("build SIR: %w", err)
	}

	switch format {
	case "jsonl":
		facts := extractFacts(doc)
		if encErr := serializeJSONL(facts, w); encErr != nil {
			return fmt.Errorf("encode jsonl: %w", encErr)
		}
		return nil
	case "smt2":
		facts := extractFacts(doc)
		if encErr := serializeSMT2(facts, w); encErr != nil {
			return fmt.Errorf("encode smt2: %w", encErr)
		}
		return nil
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(doc); encErr != nil {
			return fmt.Errorf("encode SIR: %w", encErr)
		}
		return nil
	}
}

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
