package cel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TraceResult holds a CEL-based predicate evaluation trace.
// It implements evaluation.TraceRenderer for integration with
// the existing finding enrichment pipeline.
type TraceResult struct {
	ControlID  kernel.ControlID `json:"control_id"`
	AssetID    asset.ID         `json:"asset_id"`
	Expression string           `json:"expression"`
	Result     bool             `json:"result"`
	Error      string           `json:"error,omitempty"`
}

// RenderText writes a human-readable trace to the writer.
func (r *TraceResult) RenderText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "Control:\t%s\n", r.ControlID)
	fmt.Fprintf(tw, "Asset:\t%s\n", r.AssetID)
	fmt.Fprintf(tw, "Result:\t%v\n", r.Result)
	if r.Error != "" {
		fmt.Fprintf(tw, "Error:\t%s\n", r.Error)
	}
	fmt.Fprintf(tw, "\nCEL Expression:\n%s\n", r.Expression)
	return tw.Flush()
}

// RenderJSON writes the trace as JSON to the writer.
func (r *TraceResult) RenderJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// BuildTrace compiles and evaluates a control's predicate against an
// asset, returning a TraceResult with the CEL expression and
// evaluation result. Returns (nil, error) for missing inputs (a nil
// control or asset is a programming defect, not data absence) or for
// compiler initialization failure. Compile and evaluate errors are
// captured in the returned TraceResult's Error field rather than
// surfaced as a Go error so callers can still render a partial trace.
func BuildTrace(
	ctl *policy.ControlDefinition,
	a *asset.Asset,
	snapshot *asset.Snapshot,
) (*TraceResult, error) {
	if ctl == nil {
		return nil, errors.New("BuildTrace: control is nil")
	}
	if a == nil {
		return nil, errors.New("BuildTrace: asset is nil")
	}

	compiler, err := NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("BuildTrace: CEL compiler init: %w", err)
	}

	cp, err := compiler.Compile(ctl.UnsafePredicate)
	if err != nil {
		// Capture both the original compile error and any
		// predicate-to-expression conversion error so a malformed
		// predicate (e.g. unsupported literal type, missing
		// operator) doesn't disappear into a "compile" message
		// that names the wrong root cause. The earlier shape
		// silently dropped the conversion error, leaving operators
		// without the actual reason the trace is incomplete.
		expr, exprErr := PredicateToExpr(ctl.UnsafePredicate)
		errMsg := fmt.Sprintf("CEL compile: %v", err)
		if exprErr != nil {
			errMsg = fmt.Sprintf("%s; predicate-to-expression: %v", errMsg, exprErr)
		}
		return &TraceResult{
			ControlID:  ctl.ID,
			AssetID:    a.ID,
			Expression: expr,
			Error:      errMsg,
		}, nil
	}

	var identities []asset.CloudIdentity
	if snapshot != nil {
		identities = snapshot.Identities
	}

	result, evalErr := Evaluate(cp, *a, identities, ctl.Params.Raw())

	tr := &TraceResult{
		ControlID:  ctl.ID,
		AssetID:    a.ID,
		Expression: string(cp.Expression),
		Result:     result,
	}
	if evalErr != nil {
		// Evaluation failures get returned as the function's error
		// so callers can decide whether to abort their workflow,
		// while the readable form still lives on tr.Error for
		// rendering. The earlier shape only captured the message
		// on tr.Error, so a downstream caller that ignored the
		// (TraceResult, nil) pair processed an inconclusive trace
		// as if it were definitive.
		tr.Error = fmt.Sprintf("CEL eval: %v", evalErr)
		return tr, evalErr
	}
	return tr, nil
}
