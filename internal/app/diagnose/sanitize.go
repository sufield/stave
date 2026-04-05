package diagnose

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/core/kernel"
)

// SanitizeDiagnosisReport returns a deep copy of the report with asset
// identifiers replaced by deterministic tokens.
func SanitizeDiagnosisReport(s kernel.IDSanitizer, r *diagnosis.Report) *diagnosis.Report {
	if r == nil {
		return nil
	}
	out := *r
	out.Issues = make([]diagnosis.Insight, len(r.Issues))
	for i, d := range r.Issues {
		out.Issues[i] = sanitizeDiagnosisIssue(s, d)
	}
	return &out
}

func sanitizeDiagnosisIssue(s kernel.IDSanitizer, d diagnosis.Insight) diagnosis.Insight {
	if d.AssetID == "" {
		return d
	}
	raw := string(d.AssetID)
	token := s.ID(raw)
	d.AssetID = asset.ID(token)
	d.Evidence = strings.ReplaceAll(d.Evidence, raw, token)
	return d
}
