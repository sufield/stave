package cel

import "testing"

func TestMustPredicateEval_Succeeds(t *testing.T) {
	eval := MustPredicateEval()
	if eval == nil {
		t.Fatal("MustPredicateEval returned nil")
	}
}
