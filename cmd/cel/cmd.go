// Package cel implements the stave cel command group for interactive
// CEL expression evaluation against observation data.
package cel

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

// NewCmd creates the cel parent command with eval subcommand.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cel",
		Short: "CEL expression tools",
		Long:  "Interactive CEL expression evaluation against observation data." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(newEvalCmd())
	return cmd
}

func newEvalCmd() *cobra.Command {
	var expr, inputPath, assetType, format string
	var useStdin bool

	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Evaluate a CEL expression against observation assets",
		Long: `Evaluate a CEL expression against assets from an observation file.
Reports which assets match and which do not.

Inputs:
  --expr         CEL expression to evaluate (required)
  --input        Path to observation JSON file
  --stdin        Read observation JSON from stdin
  --asset-type   Filter to assets of this type
  --format       Output format: text or json (default: text)

Exit Codes:
  0   Evaluation completed
  2   Invalid input
  4   Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave cel eval --expr 'properties["storage"]["versioning"]["enabled"] == false' --input obs.json
  cat obs.json | stave cel eval --expr 'properties["type"] == "aws_s3_bucket"' --stdin`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if expr == "" {
				return &ui.UserError{Err: errors.New("--expr is required")}
			}
			if inputPath == "" && !useStdin {
				return &ui.UserError{Err: errors.New("either --input or --stdin is required")}
			}
			return runCELEval(cmd.OutOrStdout(), cmd.ErrOrStderr(), cmd.InOrStdin(), expr, inputPath, assetType, format, useStdin)
		},
	}

	cmd.Flags().StringVar(&expr, "expr", "", "CEL expression to evaluate (required)")
	cmd.Flags().StringVar(&inputPath, "input", "", "Path to observation JSON file")
	cmd.Flags().BoolVar(&useStdin, "stdin", false, "Read observation JSON from stdin")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "Filter to assets of this type")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}

func runCELEval(stdout, stderr io.Writer, stdin io.Reader, expr, inputPath, assetType, format string, useStdin bool) error {
	// Validate format up front. This is a guard, not a render dispatch
	// (the rendering itself lives in stave.EvalCEL), so it does not trip
	// the inline-format-switch lint.
	if format != "json" && format != "text" && format != "" {
		return &ui.UserError{Err: fmt.Errorf("unknown format %q (valid: text, json)", format)}
	}

	var data []byte
	var err error
	if useStdin {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = fsutil.ReadFileLimited(inputPath)
	}
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read input: %w", err)}
	}

	res, err := stave.EvalCEL(data, expr, assetType, format)
	if res.SnapshotCount > 1 {
		// Bundle contains multiple snapshots; all snapshots' assets are
		// flattened into one list. Notify the operator of the scope.
		fmt.Fprintf(stderr, "Note: input contains %d snapshots; evaluating expression against the union of all assets across snapshots.\n", res.SnapshotCount)
	}
	// Write any rendered output before handling the error: the text
	// renderer emits its per-asset table even when it reports that the
	// evaluation completed with errors.
	if len(res.Output) > 0 {
		if _, werr := stdout.Write(res.Output); werr != nil {
			return fmt.Errorf("write output: %w", werr)
		}
	}
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve the exit-4 message verbatim.
	}
	return nil
}
