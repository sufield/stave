package stave

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/app/celeval"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// celBridge adapts the stave CEL environment to celeval.PredicateEvaluator.
type celBridge struct{}

func (b *celBridge) EvalBool(expr string, props map[string]any) (bool, error) {
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

// CELResult carries the rendered output of [EvalCEL] plus the snapshot
// count, so the CLI can warn when a multi-snapshot bundle was flattened.
// Output is populated even when the returned error is non-nil for the
// text format: a "evaluation completed with N errors" outcome still emits
// the per-asset table.
type CELResult struct {
	Output        []byte
	SnapshotCount int
}

// EvalCEL evaluates a raw CEL expression against the assets in an
// observation snapshot or bundle (JSON) and renders the result in the
// requested format ("json", or "text"/"" for the human summary). A parse
// failure wraps [ErrInvalidInput]. It is the library entry point behind
// `stave cel`.
func EvalCEL(data []byte, expression, assetType, format string) (CELResult, error) {
	assets, snapshotCount, err := parseAssets(data)
	if err != nil {
		return CELResult{}, fmt.Errorf("parse observation: %w: %w", err, ErrInvalidInput)
	}

	result, err := celeval.Eval(celeval.Input{
		Expression: expression,
		Assets:     assets,
		AssetType:  kernel.AssetType(assetType),
		Evaluator:  &celBridge{},
	})
	if err != nil {
		return CELResult{SnapshotCount: snapshotCount}, fmt.Errorf("evaluate: %w", err)
	}

	var buf bytes.Buffer
	if format == "json" {
		if err := jsonutil.WriteIndented(&buf, result); err != nil {
			return CELResult{SnapshotCount: snapshotCount}, fmt.Errorf("write JSON output: %w", err)
		}
	} else {
		// The text renderer writes its table to buf even when it reports
		// evaluation errors, so return the bytes alongside the error.
		if rerr := renderCELText(&buf, result); rerr != nil {
			return CELResult{Output: buf.Bytes(), SnapshotCount: snapshotCount}, fmt.Errorf("render output: %w", rerr)
		}
	}
	return CELResult{Output: buf.Bytes(), SnapshotCount: snapshotCount}, nil
}
