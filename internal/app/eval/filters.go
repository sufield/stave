package eval

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// ControlFilter selects which controls to evaluate.
type ControlFilter struct {
	MinSeverity      policy.Severity
	ControlID        kernel.ControlID
	ExcludeControlID []kernel.ControlID
	Compliance       string
}

// Enabled reports whether any filter criteria are set.
func (f ControlFilter) Enabled() bool {
	return f.MinSeverity != policy.SeverityNone || f.ControlID != "" || len(f.ExcludeControlID) > 0 || f.Compliance != ""
}

// FilterControls returns only the controls that match the filter criteria.
func FilterControls(invs []policy.ControlDefinition, f ControlFilter) ([]policy.ControlDefinition, error) {
	if f.MinSeverity != policy.SeverityNone && !f.MinSeverity.IsValid() {
		return nil, fmt.Errorf("invalid --min-severity %s (use: critical, high, medium, low, info)", f.MinSeverity)
	}

	excluded := make(map[kernel.ControlID]struct{}, len(f.ExcludeControlID))
	for _, id := range f.ExcludeControlID {
		excluded[id] = struct{}{}
	}

	filtered := make([]policy.ControlDefinition, 0, len(invs))
	for _, ctl := range invs {
		if f.matches(ctl, excluded) {
			filtered = append(filtered, ctl)
		}
	}

	return filtered, nil
}

// matches reports whether a single control passes all filter criteria.
func (f ControlFilter) matches(ctl policy.ControlDefinition, excluded map[kernel.ControlID]struct{}) bool {
	if f.ControlID != "" && ctl.ID != f.ControlID {
		return false
	}
	if _, ok := excluded[ctl.ID]; ok {
		return false
	}
	if f.MinSeverity != policy.SeverityNone && !ctl.Severity.Gte(f.MinSeverity) {
		return false
	}
	if f.Compliance != "" && !ctl.HasCompliance(f.Compliance) {
		return false
	}
	return true
}
