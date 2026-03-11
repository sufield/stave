package engine

import (
	"testing"

	"github.com/sufield/stave/internal/domain/policy"
)

// TestStrategyFor_CoversAllEvaluatableTypes guards against EvaluatableTypes
// and strategyFor diverging. Every evaluatable control type must map to a
// concrete strategy (not unsupportedStrategy).
func TestStrategyFor_CoversAllEvaluatableTypes(t *testing.T) {
	runner := &Runner{}
	for _, ct := range policy.EvaluatableTypes {
		ctl := &policy.ControlDefinition{Type: ct}
		s := runner.strategyFor(ctl)
		if _, ok := s.(*unsupportedStrategy); ok {
			t.Errorf("EvaluatableType %q falls through to unsupportedStrategy in strategyFor", ct)
		}
	}
}
