// Package cel implements the stave cel command group for interactive
// CEL expression evaluation against observation data.
package cel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/celeval"
	stavecel "github.com/sufield/stave/internal/cel"
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
			return runCELEval(cmd.OutOrStdout(), cmd.InOrStdin(), expr, inputPath, assetType, format, useStdin)
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

func runCELEval(stdout io.Writer, stdin io.Reader, expr, inputPath, assetType, format string, useStdin bool) error {
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

	assets, err := parseAssets(data)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse observation: %w", err)}
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

func parseAssets(data []byte) ([]asset.Asset, error) {
	// Try single snapshot format first.
	var snapshot struct {
		Assets []asset.Asset `json:"assets"`
	}
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}
	if len(snapshot.Assets) > 0 {
		return snapshot.Assets, nil
	}

	// Try bundle format with snapshots array.
	var bundle struct {
		Snapshots []struct {
			Assets []asset.Asset `json:"assets"`
		} `json:"snapshots"`
	}
	if err := json.Unmarshal(data, &bundle); err == nil && len(bundle.Snapshots) > 0 {
		last := bundle.Snapshots[len(bundle.Snapshots)-1]
		return last.Assets, nil
	}

	return nil, errors.New("no assets found in input")
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
