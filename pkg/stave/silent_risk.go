package stave

import "github.com/sufield/stave/pkg/stave/internal/applycore"

// SilentRiskControl identifies a control that may have produced a
// false PASS verdict because required observation fields were absent
// from the snapshot. The control's predicate references fields that
// no asset provided, so the evaluator could not determine whether the
// asset is safe or unsafe — and defaulted to PASS.
type SilentRiskControl struct {
	ControlID     ControlID `json:"control_id"`
	Severity      Severity  `json:"severity"`
	MissingFields []string  `json:"missing_fields"`
}

func convertSilentRisks(src []applycore.SilentRiskControl) []SilentRiskControl {
	if len(src) == 0 {
		return nil
	}
	out := make([]SilentRiskControl, len(src))
	for i, s := range src {
		out[i] = SilentRiskControl{
			ControlID:     ControlID(s.ControlID),
			Severity:      Severity(s.Severity),
			MissingFields: s.MissingFields,
		}
	}
	return out
}
