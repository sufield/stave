// Package validatemapping implements `stave validate-mapping` — a
// pre-flight check for Steampipe→Stave transform contracts. It
// answers three questions about a mapping file before an agent uses
// it to populate observations:
//
//  1. Structural: required fields present, operation kinds recognised,
//     each kind has its mandatory subfields.
//  2. Schema fit: every operation path points to a property the
//     per-asset JSON Schema declares (or warns when the schema does
//     not register that path — `additionalProperties: true` would
//     accept it but no control reads it).
//  3. Catalog coverage: how many of the property paths the control
//     catalog actually reads for this asset type are populated by the
//     mapping, and which high-control-count paths are missing.
//
// The command does not execute the mapping. Authoring-time validation
// only — the YAML interpreter lives in examples/agents/stave_transform.py
// and runs at observation-build time. Use this to catch typos, missing
// operations, and coverage holes before the agent ships a snapshot.
package validatemapping

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	File        string
	ControlsDir string
	ChainsDir   string
	Format      string
	Strict      bool
}

// NewCmd constructs the `validate-mapping` command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format:      "text",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	cmd := &cobra.Command{
		Use:   "validate-mapping",
		Short: "Validate a Steampipe→Stave mapping file before use",
		Long: `Validate inspects a contracts/steampipe/<asset_type>.yaml mapping and
reports whether it can produce a schema-valid observation for the
declared asset type, plus how much of the catalog's read surface it
covers.

Three checks:
  1. Structural — required fields, recognised operation kinds, each
     kind's mandatory subfields.
  2. Schema fit — every operation path resolves to a property declared
     in schemas/observation/v1/asset-types/<asset_type>.schema.json
     (paths the schema does not declare are warned, not failed —
     additionalProperties is true).
  3. Catalog coverage — how many of the property paths the control +
     chain catalog reads for this asset type are populated, with the
     highest-control-count gaps surfaced.

Inputs:
  --file FILE        Mapping YAML to validate (required)
  --controls DIR     Control catalog (default: controls)
  --chains DIR       Chain catalog (default: chains)
  --format F         text (default) | json
  --strict           Treat coverage gaps and unknown-to-schema paths
                     as failures (exit 3) instead of warnings.

Exit codes:
  0   Mapping is valid (warnings may apply unless --strict)
  2   Invalid input (missing flag, unreadable file, bad format)
  3   Mapping is invalid (structural or, with --strict, coverage gap)
  4   Internal error
`,
		Example: `  stave validate-mapping --file contracts/steampipe/aws_s3_bucket.yaml
  stave validate-mapping --file contracts/steampipe/aws_iam_role.yaml --strict
  stave validate-mapping --file contracts/steampipe/aws_kms_key.yaml --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.File, "file", "", "mapping YAML file to validate (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "", "chain catalog directory (default: embedded chains)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().BoolVar(&opts.Strict, "strict", false, "treat coverage gaps and unknown-to-schema paths as failures")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options) error {
	if strings.TrimSpace(opts.File) == "" {
		return &ui.UserError{Err: errors.New("--file is required")}
	}
	// Validate the format up front (guard, not a render dispatch — the
	// rendering lives in pkg/stave — so this does not trip the
	// inline-format-switch lint).
	if opts.Format != "text" && opts.Format != "json" && opts.Format != "" {
		return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
	}

	raw, err := fsutil.ReadFileLimited(opts.File)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read %s: %w", opts.File, err)}
	}

	out, invalid, err := stave.ValidateMapping(ctx, opts.File, raw, opts.ControlsDir, opts.ChainsDir, opts.Format, opts.Strict)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("load controls"/"render ..."); preserve exit 4.
	}

	if _, werr := w.Write(out); werr != nil {
		return fmt.Errorf("write validation report: %w", werr)
	}

	if invalid {
		return fmt.Errorf("mapping %s failed validation: %w", opts.File, ui.ErrDiagnosticsFound)
	}
	return nil
}
