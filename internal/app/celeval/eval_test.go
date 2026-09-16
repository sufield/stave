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

func (m *mockEvaluator) EvalBool(_ Expression, _ map[string]any) (bool, error) {
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

func TestAssetResults_DomainMethods(t *testing.T) {
	results := AssetResults{
		{AssetID: "a1", AssetType: "s3_bucket", Result: true},
		{AssetID: "a2", AssetType: "ec2_instance", Result: false},
		{AssetID: "a3", AssetType: "iam_role", Result: false, Error: "eval error"},
	}

	if results.Len() != 3 {
		t.Errorf("Len() = %d, want 3", results.Len())
	}

	firing := results.Firing()
	if firing.Len() != 1 {
		t.Errorf("Firing().Len() = %d, want 1", firing.Len())
	}
	if firing[0].AssetID != "a1" {
		t.Errorf("Firing()[0].AssetID = %s, want a1", firing[0].AssetID)
	}

	errs := results.Errors()
	if errs.Len() != 1 {
		t.Errorf("Errors().Len() = %d, want 1", errs.Len())
	}
	if errs[0].AssetID != "a3" {
		t.Errorf("Errors()[0].AssetID = %s, want a3", errs[0].AssetID)
	}

	var empty AssetResults
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.Firing() != nil {
		t.Error("empty.Firing() should return nil")
	}
	if empty.Errors() != nil {
		t.Error("empty.Errors() should return nil")
	}
}
