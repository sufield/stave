package celeval

import (
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

type mockEvaluator struct {
	result bool
	err    error
}

func (m *mockEvaluator) EvalBool(_ string, _ map[string]any) (bool, error) {
	return m.result, m.err
}

func TestEval_BoolResultCorrect(t *testing.T) {
	assets := []asset.Asset{
		{ID: "bucket1", Type: kernel.AssetType("s3_bucket"), Properties: map[string]any{"public": true}},
	}

	result, err := Eval(Input{
		Expression: "properties.public == true",
		Assets:     assets,
		Evaluator:  &mockEvaluator{result: true},
	})

	if err != nil {
		t.Fatal(err)
	}
	if result.TotalFire != 1 {
		t.Errorf("fire = %d, want 1", result.TotalFire)
	}
}

func TestEval_UndefinedFieldProducesError(t *testing.T) {
	assets := []asset.Asset{
		{ID: "bucket1", Type: "s3_bucket", Properties: map[string]any{}},
	}

	result, err := Eval(Input{
		Expression: "properties.nonexistent == true",
		Assets:     assets,
		Evaluator:  &mockEvaluator{err: errors.New("undefined field: nonexistent")},
	})

	if err != nil {
		t.Fatal(err)
	}
	if result.TotalError != 1 {
		t.Errorf("errors = %d, want 1", result.TotalError)
	}
	if result.Assets[0].Error == "" {
		t.Error("expected error message on asset result")
	}
}

func TestEval_AssetTypeFilter(t *testing.T) {
	assets := []asset.Asset{
		{ID: "bucket1", Type: "s3_bucket", Properties: map[string]any{}},
		{ID: "instance1", Type: "ec2_instance", Properties: map[string]any{}},
	}

	result, err := Eval(Input{
		Expression: "true",
		Assets:     assets,
		AssetType:  "s3_bucket",
		Evaluator:  &mockEvaluator{result: true},
	})

	if err != nil {
		t.Fatal(err)
	}
	if len(result.Assets) != 1 {
		t.Errorf("assets = %d, want 1 (filtered)", len(result.Assets))
	}
}
