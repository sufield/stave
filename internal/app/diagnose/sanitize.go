package diagnose

import (
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// SanitizeDiagnosisReport returns a deep copy of the report with asset
// identifiers replaced by deterministic tokens.
func SanitizeDiagnosisReport(s kernel.IDSanitizer, r *diagnosis.Report) *diagnosis.Report {
	if r == nil {
		return nil
	}
	out := *r
	out.Issues = make([]diagnosis.Issue, len(r.Issues))
	for i, d := range r.Issues {
		out.Issues[i] = sanitizeDiagnosisIssue(s, d)
	}
	return &out
}

func sanitizeDiagnosisIssue(s kernel.IDSanitizer, d diagnosis.Issue) diagnosis.Issue {
	if d.AssetID == "" {
		return d
	}
	raw := string(d.AssetID)
	token := s.ID(raw)
	d.AssetID = asset.ID(token)
	d.Evidence = strings.ReplaceAll(d.Evidence, raw, token)
	return d
}
