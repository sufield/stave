// Package cel implements the stave cel command group for interactive
// CEL expression evaluation against observation data.
package cel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/app/celeval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
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

// celBridge adapts the stave CEL environment to the celeval.PredicateEvaluator interface.
type celBridge struct{}

func (b *celBridge) EvalBool(expr string, props map[string]any) (bool, error) {
	// Create a minimal CEL environment and compile the raw expression.
	celEnv, err := stavecel.NewEnv()
	if err != nil {
		return false, fmt.Errorf("create CEL environment: %w", err)
	}

	ast, issues := celEnv.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return false, fmt.Errorf("compile expression: %w", issues.Err())
	}

	prg, err := celEnv.Program(ast)
	if err != nil {
		return false, fmt.Errorf("program expression: %w", err)
	}

	activation := map[string]any{
		"properties": props,
		"params":     map[string]any{},
		"identities": []any{},
		"identity":   map[string]any{},
	}

	out, _, err := prg.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("evaluate: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expected bool result, got %T", out.Value())
	}
	return result, nil
}

func runCELEval(stdout, stderr io.Writer, stdin io.Reader, expr, inputPath, assetType, format string, useStdin bool) error {
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

	assets, snapshotCount, err := parseAssets(data)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse observation: %w", err)}
	}
	if snapshotCount > 1 {
		// Bundle contains multiple snapshots. The previous behavior
		// silently used only the last snapshot's assets, so a user
		// running `stave cel` against a multi-snapshot bundle saw
		// results that omitted assets that only existed in earlier
		// snapshots. Now all snapshots' assets are flattened into
		// one list, with a stderr notice so the operator knows the
		// scope they're seeing.
		fmt.Fprintf(stderr, "Note: input contains %d snapshots; evaluating expression against the union of all assets across snapshots.\n", snapshotCount)
	}

	bridge := &celBridge{}

	result, err := celeval.Eval(celeval.Input{
		Expression: expr,
		Assets:     assets,
		AssetType:  assetType,
		Evaluator:  bridge,
	})
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	if format == "json" {
		return jsonutil.WriteIndented(stdout, result)
	}

	return renderCELText(stdout, result)
}

// parseAssets returns the union of all assets across the input
// (single snapshot or multi-snapshot bundle) plus the bundle's
// snapshot count. The previous behavior used only the *last*
// snapshot's assets in the bundle case, so a `stave cel`
// expression run against a multi-snapshot input silently omitted
// every asset that didn't survive into the final snapshot — the
// classic "where did my asset go" reporting bug.
//
// Snapshots are taken in order; an asset that appears in multiple
// snapshots is included once per snapshot it appears in. Callers
// that want to dedupe by AssetID can do so on the returned slice.
func parseAssets(data []byte) ([]asset.Asset, int, error) {
	// Try single snapshot format first.
	var snapshot struct {
		Assets []asset.Asset `json:"assets"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, 0, fmt.Errorf("parse JSON: %w", err)
	}
	if len(snapshot.Assets) > 0 {
		return snapshot.Assets, 1, nil
	}

	// Try bundle format with snapshots array.
	var bundle struct {
		Snapshots []struct {
			Assets []asset.Asset `json:"assets"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(data, &bundle); err == nil && len(bundle.Snapshots) > 0 {
		var all []asset.Asset
		for _, snap := range bundle.Snapshots {
			all = append(all, snap.Assets...)
		}
		return all, len(bundle.Snapshots), nil
	}

	return nil, 0, errors.New("no assets found in input")
}

func renderCELText(w io.Writer, result *celeval.EvalResult) error {
	fmt.Fprintf(w, "Expression: %s\n\n", result.Expression)
	for _, ar := range result.Assets {
		status := "PASS"
		if ar.Error != "" {
			status = "ERROR"
		} else if ar.Result {
			status = "FIRE"
		}
		fmt.Fprintf(w, "  %-6s %s (%s)\n", status, ar.AssetID, ar.AssetType)
		if ar.Error != "" {
			fmt.Fprintf(w, "         error: %s\n", ar.Error)
		}
	}
	fmt.Fprintf(w, "\nFire: %d  Pass: %d  Error: %d\n", result.TotalFire, result.TotalPass, result.TotalError)

	if result.TotalError > 0 {
		return fmt.Errorf("evaluation completed with %d errors", result.TotalError)
	}
	return nil
}
