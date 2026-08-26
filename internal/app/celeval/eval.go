// Package celeval evaluates a single CEL expression against observation
// assets for interactive control development and debugging.
package celeval

import (
	"errors"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// AssetResult holds the evaluation result for one asset.
type AssetResult struct {
	AssetID   asset.ID         `json:"asset_id"`
	AssetType kernel.AssetType `json:"asset_type"`
	Result    bool             `json:"result"`
	Error     string           `json:"error,omitempty"`
}

// EvalResult holds the full evaluation output.
type EvalResult struct {
	Expression string        `json:"expression"`
	Assets     []AssetResult `json:"assets"`
	TotalFire  int           `json:"total_fire"`
	TotalPass  int           `json:"total_pass"`
	TotalError int           `json:"total_error"`
}

// PredicateEvaluator evaluates a CEL expression against an asset property map.
type PredicateEvaluator interface {
	EvalBool(expr string, props map[string]any) (bool, error)
}

// Input configures the evaluation.
type Input struct {
	Expression string
	Assets     []asset.Asset
	AssetType  kernel.AssetType // filter to this type if non-empty
	Evaluator  PredicateEvaluator
}

// Eval runs a CEL expression against matching assets.
func Eval(in Input) (*EvalResult, error) {
	if in.Evaluator == nil {
		return nil, errors.New("evaluator is required")
	}

	result := &EvalResult{Expression: in.Expression}

	for i := range in.Assets {
		a := &in.Assets[i]
		if in.AssetType != "" && !a.IsType(string(in.AssetType)) {
			continue
		}

		props := a.Map()
		val, err := in.Evaluator.EvalBool(in.Expression, props)

		ar := AssetResult{
			AssetID:   a.ID,
			AssetType: a.Type,
			Result:    val,
		}
		if err != nil {
			ar.Error = err.Error()
			result.TotalError++
		} else if val {
			result.TotalFire++
		} else {
			result.TotalPass++
		}

		result.Assets = append(result.Assets, ar)
	}

	return result, nil
}
