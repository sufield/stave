package cel

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
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

// BuildTrace compiles and evaluates a control's predicate against an asset,
// returning a TraceResult with the CEL expression and evaluation result.
func BuildTrace(
	ctl *policy.ControlDefinition,
	a *asset.Asset,
	snapshot *asset.Snapshot,
) *TraceResult {
	if ctl == nil || a == nil {
		return nil
	}

	compiler, err := NewCompiler()
	if err != nil {
		return &TraceResult{
			ControlID: ctl.ID,
			AssetID:   a.ID,
			Error:     fmt.Sprintf("CEL compiler init: %v", err),
		}
	}

	cp, err := compiler.Compile(ctl.UnsafePredicate)
	if err != nil {
		expr, _ := PredicateToExpr(ctl.UnsafePredicate)
		return &TraceResult{
			ControlID:  ctl.ID,
			AssetID:    a.ID,
			Expression: expr,
			Error:      fmt.Sprintf("CEL compile: %v", err),
		}
	}

	var identities []asset.CloudIdentity
	if snapshot != nil {
		identities = snapshot.Identities
	}

	result, evalErr := Evaluate(cp, *a, identities)

	tr := &TraceResult{
		ControlID:  ctl.ID,
		AssetID:    a.ID,
		Expression: cp.Expression,
		Result:     result,
	}
	if evalErr != nil {
		tr.Error = fmt.Sprintf("CEL eval: %v", evalErr)
	}
	return tr
}
