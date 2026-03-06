// Package output provides shared helpers for finding output adapters.
package output

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
)

// FindingEnricher enriches raw evaluation findings with remediation guidance.
type FindingEnricher interface {
	EnrichFindings(evaluation.Result) []remediation.Finding
}

// Enrich enriches findings from the result and returns a fully-sanitized
// EnrichedResult suitable for passing to a FindingMarshaler. All metadata
// that needs sanitization (findings, skipped assets, input hashes) is
// handled here so marshalers receive clean data.
func Enrich(enricher FindingEnricher, sanitizer kernel.Sanitizer, result evaluation.Result) appcontracts.EnrichedResult {
	findings := PrepareFindings(enricher, sanitizer, result)
	skippedAssets := result.SkippedAssets
	run := result.Run
	if sanitizer != nil {
		skippedAssets = SanitizeSkippedAssets(sanitizer, skippedAssets)
		run.InputHashes = SanitizeInputHashKeys(sanitizer, run.InputHashes)
	}
	return appcontracts.EnrichedResult{
		Result:        result,
		Findings:      findings,
		SkippedAssets: skippedAssets,
		Run:           run,
	}
}

// PrepareFindings enriches findings from the result and optionally sanitizes them.
// If sanitizer is nil, sanitization is skipped.
func PrepareFindings(enricher FindingEnricher, sanitizer kernel.Sanitizer, result evaluation.Result) []remediation.Finding {
	if enricher == nil {
		panic("precondition failed: PrepareFindings requires non-nil enricher")
	}
	findings := enricher.EnrichFindings(result)
	if sanitizer != nil {
		findings = SanitizeFindings(sanitizer, findings)
	}
	return findings
}
