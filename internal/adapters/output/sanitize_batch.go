package output

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// SanitizeBaselineEntries returns copies with asset IDs sanitized.
func SanitizeBaselineEntries(s kernel.Sanitizer, entries []evaluation.BaselineEntry) []evaluation.BaselineEntry {
	if s == nil || len(entries) == 0 {
		return entries
	}
	res := make([]evaluation.BaselineEntry, len(entries))
	for i, e := range entries {
		e.AssetID = asset.ID(s.ID(string(e.AssetID)))
		res[i] = e
	}
	return res
}

// SanitizeObservationDelta returns a copy with asset IDs in changes sanitized.
func SanitizeObservationDelta(s kernel.Sanitizer, delta asset.ObservationDelta) asset.ObservationDelta {
	if s == nil || len(delta.Changes) == 0 {
		return delta
	}
	changes := make([]asset.Diff, len(delta.Changes))
	for i, c := range delta.Changes {
		c.AssetID = asset.ID(s.ID(string(c.AssetID)))
		changes[i] = c
	}
	delta.Changes = changes
	return delta
}
