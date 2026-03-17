package output

import (
	"github.com/samber/lo"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
)

// SanitizeReport returns a sanitized copy of a diagnosis report.
func SanitizeReport(s kernel.Sanitizer, r *diagnosis.Report) *diagnosis.Report {
	if r == nil {
		return nil
	}
	return r.Sanitized(s)
}

// SanitizeBaselineEntries returns copies with asset IDs sanitized.
func SanitizeBaselineEntries(s kernel.Sanitizer, entries []evaluation.BaselineEntry) []evaluation.BaselineEntry {
	if s == nil || len(entries) == 0 {
		return entries
	}
	return lo.Map(entries, func(e evaluation.BaselineEntry, _ int) evaluation.BaselineEntry {
		e.AssetID = asset.ID(s.ID(string(e.AssetID)))
		return e
	})
}

// SanitizeObservationDelta returns a copy with asset IDs in changes sanitized.
func SanitizeObservationDelta(s kernel.Sanitizer, delta asset.ObservationDelta) asset.ObservationDelta {
	if s == nil || len(delta.Changes) == 0 {
		return delta
	}
	changes := make([]asset.AssetDiff, len(delta.Changes))
	for i, c := range delta.Changes {
		c.AssetID = asset.ID(s.ID(string(c.AssetID)))
		changes[i] = c
	}
	delta.Changes = changes
	return delta
}
