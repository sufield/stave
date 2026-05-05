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
	"errors"
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
controls and observations as a deterministic JSON document.

The SIR is the vendor-neutral fact set the Z3 solver consumes for compound
risk reasoning. It carries every control fact, asset, identity (with
transitive role chains), effective-permission edge, and exposure window
that the engine's evaluation pipeline produces — but stripped of
infrastructure noise (file paths, git metadata, tool versions).

Inputs:
  --controls, -i      Control definitions directory (default: controls)
  --observations, -o  Observation snapshots directory (default: observations)
  --format, -f        Output format: json (default: json)
  --now               RFC3339 timestamp for deterministic output

Outputs:
  stdout: SIR JSON document.
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
  stave export-sir | jq .`,
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
	flags.StringVarP(&opts.Format, cliflags.FlagFormat, "f", "json", "output format: json")
	flags.StringVar(&opts.Now, flagNow, "", "override current time (RFC3339) for deterministic output")

	return cmd
}

// run is the testable command body. UserError wraps input
// problems (mapped to exit code 2 by ui.ExitCode); plain errors
// fall through to exit code 4 (ExitInternal) — that's the
// convention the rest of the cmd/ tree follows.
func run(ctx context.Context, w io.Writer, opts *options, newCtlRepo compose.CtlRepoFactory, newObsRepo compose.ObsRepoFactory, newCELEvaluator compose.CELEvaluatorFactory) error {
	if !strings.EqualFold(opts.Format, "json") {
		return &ui.UserError{Err: errors.New("--format must be json (only supported format today)")}
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

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(doc); encErr != nil {
		return fmt.Errorf("encode SIR: %w", encErr)
	}
	return nil
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
