package yaml

import "testing"

func TestParsePredicate_Nil(t *testing.T) {
	pred, err := ParsePredicate(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pred != nil {
		t.Fatal("nil input should return nil predicate")
	}
}

func TestParsePredicate_SimpleAll(t *testing.T) {
	input := map[string]any{
		"all": []any{
			map[string]any{
				"field": "properties.storage.kind",
				"op":    "eq",
				"value": "bucket",
			},
		},
	}
	pred, err := ParsePredicate(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pred == nil {
		t.Fatal("expected non-nil predicate")
	}
	if len(pred.All) != 1 {
		t.Errorf("expected 1 rule in All, got %d", len(pred.All))
	}
}

func TestParsePredicate_InvalidStructure(t *testing.T) {
	input := "not-a-map"
	_, err := ParsePredicate(input)
	if err == nil {
		t.Fatal("expected error for invalid structure")
	}
}
