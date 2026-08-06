package chainforge

import (
	"testing"
)

func TestLintChain_NilChainHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("LintChain panicked on nil chain definition: %v", rec)
		}
	}()

	res := LintChain(nil, nil, nil)
	if len(res.Errors) == 0 {
		t.Errorf("expected error from LintChain on nil chain")
	}
}
