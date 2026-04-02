package eval

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Enrich enriches findings from the result and returns a fully-sanitized
// EnrichedResult suitable for passing to a FindingMarshaler. All metadata
// that needs sanitization (findings, exempted assets, input hashes) is
// handled here so marshalers receive clean data.
func Enrich(enricher remediation.FindingEnricher, sanitizer kernel.Sanitizer, result evaluation.Result) (appcontracts.EnrichedResult, error) {
	findings, err := PrepareFindings(enricher, sanitizer, result)
	if err != nil {
		return appcontracts.EnrichedResult{}, err
	}
	skippedAssets := result.ExemptedAssets
	run := result.Run
	if sanitizer != nil {
		skippedAssets = SanitizeExemptedAssets(sanitizer, skippedAssets)
		run.InputHashes = SanitizeInputHashKeys(sanitizer, run.InputHashes)
	}
	return appcontracts.EnrichedResult{
		Result:         result,
		Findings:       findings,
		ExemptedAssets: skippedAssets,
		Run:            run,
	}, nil
}

// PrepareFindings enriches findings from the result and optionally sanitizes them.
// If sanitizer is nil, sanitization is skipped.
// Returns an error if enricher is nil.
func PrepareFindings(enricher remediation.FindingEnricher, sanitizer kernel.Sanitizer, result evaluation.Result) ([]appcontracts.EnrichedFinding, error) {
	if enricher == nil {
		return nil, fmt.Errorf("enricher must not be nil")
	}
	findings := enricher.EnrichFindings(result)
	if sanitizer != nil {
		findings = SanitizeFindings(sanitizer, findings)
	}
	return toEnrichedFindings(findings), nil
}

// SanitizeFindings returns sanitized copies of a slice of findings.
func SanitizeFindings(s kernel.Sanitizer, findings []remediation.Finding) []remediation.Finding {
	out := make([]remediation.Finding, len(findings))
	for i, f := range findings {
		out[i] = f.Sanitized(s)
	}
	return out
}

// toEnrichedFindings converts remediation findings to the port-boundary type.
// The two struct types have identical underlying layouts, so this is a
// field-level copy with no semantic transformation.
func toEnrichedFindings(fs []remediation.Finding) []appcontracts.EnrichedFinding {
	out := make([]appcontracts.EnrichedFinding, len(fs))
	for i, f := range fs {
		out[i] = appcontracts.EnrichedFinding{
			Finding:         f.Finding,
			RemediationSpec: f.RemediationSpec,
			RemediationPlan: f.RemediationPlan,
		}
	}
	return out
}

// SanitizeExemptedAssets returns sanitized copies of exempted assets.
func SanitizeExemptedAssets(s kernel.Sanitizer, assets []asset.ExemptedAsset) []asset.ExemptedAsset {
	out := make([]asset.ExemptedAsset, len(assets))
	for i, a := range assets {
		out[i] = a.Sanitized(s)
	}
	return out
}

// SanitizeInputHashKeys returns a copy with file keys sanitized to basenames.
func SanitizeInputHashKeys(s kernel.Sanitizer, h *evaluation.InputHashes) *evaluation.InputHashes {
	if h == nil {
		return nil
	}
	return h.Sanitized(s)
}
