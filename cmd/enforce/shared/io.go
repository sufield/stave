package shared

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func LoadEvaluationEnvelope(path string) (*safetyenvelope.Evaluation, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read evaluation file: %w", err)
	}
	var eval safetyenvelope.Evaluation
	if err := json.Unmarshal(data, &eval); err != nil {
		return nil, fmt.Errorf("parse evaluation JSON: %w", err)
	}
	if eval.Kind != safetyenvelope.KindEvaluation {
		return nil, fmt.Errorf("invalid evaluation file kind %q (expected %q)", eval.Kind, safetyenvelope.KindEvaluation)
	}
	return &eval, nil
}

func LoadBaselineFile(path string, expectedKind kernel.OutputKind) (*evaluation.Baseline, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline file: %w", err)
	}
	var base evaluation.Baseline
	if err := json.Unmarshal(data, &base); err != nil {
		return nil, fmt.Errorf("parse baseline JSON: %w", err)
	}
	if base.Kind != expectedKind {
		return nil, fmt.Errorf("invalid baseline file kind %q (expected %q)", base.Kind, expectedKind)
	}
	if base.Findings == nil {
		base.Findings = []evaluation.BaselineEntry{}
	}
	evaluation.SortBaselineEntries(base.Findings)
	return &base, nil
}
