package eval

import (
	"fmt"

	"github.com/samber/lo"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/remediation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
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
func PrepareFindings(enricher remediation.FindingEnricher, sanitizer kernel.Sanitizer, result evaluation.Result) ([]remediation.Finding, error) {
	if enricher == nil {
		return nil, fmt.Errorf("PrepareFindings requires non-nil enricher")
	}
	findings := enricher.EnrichFindings(result)
	if sanitizer != nil {
		findings = SanitizeFindings(sanitizer, findings)
	}
	return findings, nil
}

// SanitizeFindings returns sanitized copies of a slice of findings.
func SanitizeFindings(s kernel.Sanitizer, findings []remediation.Finding) []remediation.Finding {
	return lo.Map(findings, func(f remediation.Finding, _ int) remediation.Finding { return f.Sanitized(s) })
}

// SanitizeExemptedAssets returns sanitized copies of exempted assets.
func SanitizeExemptedAssets(s kernel.Sanitizer, assets []asset.ExemptedAsset) []asset.ExemptedAsset {
	return lo.Map(assets, func(a asset.ExemptedAsset, _ int) asset.ExemptedAsset { return a.Sanitized(s) })
}

// SanitizeInputHashKeys returns a copy with file keys sanitized to basenames.
func SanitizeInputHashKeys(s kernel.Sanitizer, h *evaluation.InputHashes) *evaluation.InputHashes {
	if h == nil {
		return nil
	}
	return h.Sanitized(s)
}
