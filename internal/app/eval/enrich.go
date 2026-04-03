package eval

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
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

// SanitizeFindings returns sanitized copies of a slice of findings
// with infrastructure identifiers masked by deterministic tokens.
func SanitizeFindings(s kernel.Sanitizer, findings []remediation.Finding) []remediation.Finding {
	out := make([]remediation.Finding, len(findings))
	for i, f := range findings {
		out[i] = sanitizeFinding(f, s)
	}
	return out
}

// sanitizeFinding returns a deep copy of the Finding with infrastructure
// identifiers masked. This is presentation/privacy logic, not domain logic.
func sanitizeFinding(f remediation.Finding, s kernel.Sanitizer) remediation.Finding {
	out := f
	out.AssetID = asset.ID(s.ID(string(f.AssetID)))

	if f.Source != nil {
		src := *f.Source
		src.File = s.Path(src.File)
		out.Source = &src
	}

	if len(f.Evidence.Misconfigurations) > 0 {
		out.Evidence.Misconfigurations = make([]policy.Misconfiguration, len(f.Evidence.Misconfigurations))
		for i, m := range f.Evidence.Misconfigurations {
			out.Evidence.Misconfigurations[i] = m.Sanitized()
		}
	}

	if f.Evidence.SourceEvidence != nil {
		se := *f.Evidence.SourceEvidence
		se.IdentityStatements = sanitizeSlice(se.IdentityStatements, s)
		se.ResourceGrantees = sanitizeSlice(se.ResourceGrantees, s)
		out.Evidence.SourceEvidence = &se
	}

	if f.RemediationPlan != nil {
		plan := *f.RemediationPlan
		plan.Target.AssetID = asset.ID(s.ID(string(plan.Target.AssetID)))
		out.RemediationPlan = &plan
	}

	return out
}

// sanitizeSlice clones and replaces every element using the provided sanitizer.
func sanitizeSlice[T ~string](items []T, s kernel.Sanitizer) []T {
	if len(items) == 0 {
		return nil
	}
	out := make([]T, len(items))
	for i := range items {
		out[i] = T(s.Value(string(items[i])))
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
	sanitizedFiles := make(map[evaluation.FilePath]kernel.Digest, len(h.Files))
	for path, digest := range h.Files {
		sanitizedFiles[evaluation.FilePath(s.Path(string(path)))] = digest
	}
	return &evaluation.InputHashes{
		Files:   sanitizedFiles,
		Overall: h.Overall,
	}
}
