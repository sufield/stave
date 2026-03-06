package output

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/fp"
)

// SanitizeFindings returns sanitized copies of a slice of findings.
func SanitizeFindings(s kernel.Sanitizer, findings []remediation.Finding) []remediation.Finding {
	return fp.Map(findings, func(f remediation.Finding) remediation.Finding { return f.Sanitized(s) })
}

// SanitizeSkippedAssets returns sanitized copies of skipped assets.
func SanitizeSkippedAssets(s kernel.Sanitizer, assets []asset.SkippedAsset) []asset.SkippedAsset {
	return fp.Map(assets, func(a asset.SkippedAsset) asset.SkippedAsset { return a.Sanitized(s) })
}

// SanitizeInputHashKeys returns a copy with file keys sanitized to basenames.
func SanitizeInputHashKeys(s kernel.Sanitizer, h *evaluation.InputHashes) *evaluation.InputHashes {
	if h == nil {
		return nil
	}
	return h.Sanitized(s)
}

// SanitizeReport returns a sanitized copy of a diagnosis report.
func SanitizeReport(s kernel.Sanitizer, r *diagnosis.Report) *diagnosis.Report {
	if r == nil {
		return nil
	}
	return r.Sanitized(s)
}
