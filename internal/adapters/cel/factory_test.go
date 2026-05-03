package cel

import "testing"

func TestMustPredicateEval_Succeeds(t *testing.T) {
	t.Parallel()
	eval := MustPredicateEval()
	if eval == nil {
		t.Fatal("MustPredicateEval returned nil")
	}
}
