package engine

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

func (a *Assessor) strategyFor(ctl *policy.ControlDefinition) strategy {
	return buildStrategy(&sessionDeps{Assessor: a, span: nopSpan{}}, ctl)
}

func wrapInPointers(findings []evaluation.Finding) []*evaluation.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]*evaluation.Finding, len(findings))
	for i := range findings {
		out[i] = &findings[i]
	}
	return out
}
