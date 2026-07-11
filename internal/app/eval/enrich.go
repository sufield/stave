package eval

import (
	"errors"
	"reflect"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// Enrich enriches findings from the result and returns a fully-sanitized
// EnrichedResult suitable for passing to a FindingMarshaler. All
// metadata that needs sanitization — findings, exempted assets, input
// hashes, sidecar finding collections, metadata paths — is handled
// here so marshalers receive clean data.
func Enrich(enricher remediation.FindingEnricher, sanitizer kernel.Sanitizer, result *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
	findings, err := PrepareFindings(enricher, sanitizer, result)
	if err != nil {
		return appcontracts.EnrichedResult{}, err
	}
	markers := PrepareMarkerFindings(enricher, sanitizer, result)
	skippedAssets := result.ExemptedAssets
	run := result.Run
	resultCopy := *result
	if sanitizer != nil {
		skippedAssets = SanitizeExemptedAssets(sanitizer, skippedAssets)
		run.InputHashes = SanitizeInputHashKeys(sanitizer, run.InputHashes)
		sanitizeResultSidecars(sanitizer, &resultCopy)
	}
	return appcontracts.EnrichedResult{
		Result:         resultCopy,
		Findings:       findings,
		MarkerFindings: markers,
		ExemptedAssets: skippedAssets,
		Run:            run,
	}, nil
}

// PrepareMarkerFindings is the marker counterpart to PrepareFindings.
// Routes report.MarkerFindings through the enricher and (optionally)
// the sanitizer so renderers reuse the violation field semantics for
// asset-id masking, etc. Returns nil when the report has no marker
// findings (the common path in catalogs without marker controls).
func PrepareMarkerFindings(enricher remediation.FindingEnricher, sanitizer kernel.Sanitizer, result *evaluation.ComplianceReport) []appcontracts.EnrichedFinding {
	if enricher == nil || result == nil || len(result.MarkerFindings) == 0 {
		return nil
	}
	findings := enricher.EnrichMarkerFindings(result)
	if sanitizer != nil {
		findings = SanitizeFindings(sanitizer, findings)
	}
	return toEnrichedFindings(findings)
}

// sanitizeResultSidecars masks asset identifiers and resolved paths
// across the report sidecars that flow into the assessment alongside
// the main Findings collection. Without this, --sanitize hides
// identifiers in Findings but leaks them through RiskSignals,
// ExceptedFindings, AcknowledgedFindings, TopExposures, ChainFindings
// (CompoundFinding.AssetID + ContributingAssets), and
// Metadata.ResolvedPaths — which all carry the same identifier shapes
// the main collection does. Mutates the result copy in place.
func sanitizeResultSidecars(s kernel.Sanitizer, r *evaluation.ComplianceReport) {
	if len(r.RiskSignals) > 0 {
		signals := make(findings.ThresholdItems, len(r.RiskSignals))
		for i := range r.RiskSignals {
			item := r.RiskSignals[i]
			item.AssetID = asset.ID(s.ID(string(item.AssetID)))
			signals[i] = item
		}
		r.RiskSignals = signals
	}
	if len(r.ExceptedFindings) > 0 {
		excepted := make([]evaluation.ExceptedFinding, len(r.ExceptedFindings))
		for i, ef := range r.ExceptedFindings {
			ef.AssetID = asset.ID(s.ID(string(ef.AssetID)))
			excepted[i] = ef
		}
		r.ExceptedFindings = excepted
	}
	if len(r.AcknowledgedFindings) > 0 {
		acks := make([]policy.AcknowledgedFinding, len(r.AcknowledgedFindings))
		for i := range r.AcknowledgedFindings {
			a := r.AcknowledgedFindings[i]
			a.AssetID = asset.ID(s.ID(string(a.AssetID)))
			acks[i] = a
		}
		r.AcknowledgedFindings = acks
	}
	if len(r.TopExposures) > 0 {
		exposures := make([]findings.ExposureRank, len(r.TopExposures))
		for i, e := range r.TopExposures {
			e.AssetID = asset.ID(s.ID(string(e.AssetID)))
			exposures[i] = e
		}
		r.TopExposures = exposures
	}
	if len(r.ChainFindings) > 0 {
		chains := make([]findings.CompoundFinding, len(r.ChainFindings))
		for i := range r.ChainFindings {
			cf := r.ChainFindings[i]
			cf.AssetID = asset.ID(s.ID(string(cf.AssetID)))
			if len(cf.ContributingAssets) > 0 {
				contrib := make([]asset.ID, len(cf.ContributingAssets))
				for j, a := range cf.ContributingAssets {
					contrib[j] = asset.ID(s.ID(string(a)))
				}
				cf.ContributingAssets = contrib
			}
			chains[i] = cf
		}
		r.ChainFindings = chains
	}
	if r.Metadata.ResolvedPaths.Controls != "" {
		r.Metadata.ResolvedPaths.Controls = s.Path(r.Metadata.ResolvedPaths.Controls)
	}
	if r.Metadata.ResolvedPaths.Observations != "" {
		r.Metadata.ResolvedPaths.Observations = s.Path(r.Metadata.ResolvedPaths.Observations)
	}
}

// PrepareFindings enriches findings from the result and optionally sanitizes them.
// If sanitizer is nil, sanitization is skipped.
// Returns an error if enricher is nil.
func PrepareFindings(enricher remediation.FindingEnricher, sanitizer kernel.Sanitizer, result *evaluation.ComplianceReport) ([]appcontracts.EnrichedFinding, error) {
	if enricher == nil {
		return nil, errors.New("enricher must not be nil")
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
	for i := range findings {
		f := &findings[i]
		out[i] = sanitizeFinding(f, s)
	}
	return out
}

func sanitizeFinding(f *remediation.Finding, s kernel.Sanitizer) remediation.Finding {
	out := *f
	out.AssetID = asset.ID(s.ID(string(f.AssetID)))

	if f.HasSource() {
		src := *f.Source
		src.File = s.Path(src.File)
		out.Source = &src
	}

	if len(f.Evidence.Misconfigurations) > 0 {
		out.Evidence.Misconfigurations = make([]policy.Misconfiguration, len(f.Evidence.Misconfigurations))
		for i, m := range f.Evidence.Misconfigurations {
			m.ActualValue = sanitizeActualValue(m.ActualValue, s)
			out.Evidence.Misconfigurations[i] = m
		}
	}

	if f.Evidence.SourceEvidence != nil {
		se := *f.Evidence.SourceEvidence
		se.IdentityStatements = sanitizeSlice(se.IdentityStatements, s)
		se.ResourceGrantees = sanitizeSlice(se.ResourceGrantees, s)
		out.Evidence.SourceEvidence = &se
	}

	// ReasoningTrace carries the same observed values that flow
	// through Misconfiguration.ActualValue. The trace is built before
	// sanitization runs (engine/finding_builder.go), so sanitization
	// must mask its values alongside the Misconfigurations.
	if f.HasReasoningTrace() {
		trace := make([]evaluation.MatchedClause, len(f.ReasoningTrace))
		for i, mc := range f.ReasoningTrace {
			mc.ObservedValue = sanitizeActualValue(mc.ObservedValue, s)
			trace[i] = mc
		}
		out.ReasoningTrace = trace
	}

	// DeltaPath.CurrentValue is a string snapshot of the observed
	// value rendered for human-readable fix guidance — route it
	// through the per-field Sanitizer.
	if f.HasDelta() {
		delta := make([]policy.DeltaPath, len(f.Delta))
		for i, d := range f.Delta {
			d.CurrentValue = s.Value(d.CurrentValue)
			delta[i] = d
		}
		out.Delta = delta
	}

	if f.RemediationPlan != nil {
		plan := *f.RemediationPlan
		plan.Target.AssetID = asset.ID(s.ID(string(plan.Target.AssetID)))
		if out.RemediationSpec.Action != "" {
			syntheticAsset := asset.Asset{
				ID:     out.AssetID,
				Type:   out.AssetType,
				Vendor: out.AssetVendor,
			}
			plan.Command = remediation.FormatRemediationAction(out.RemediationSpec.Action, syntheticAsset)
		}
		out.RemediationPlan = &plan
	}

	return out
}

// sanitizeActualValue routes a Misconfiguration.ActualValue through
// the per-field Sanitizer based on its concrete type. The policy is
// type-discriminated so primitive values reach downstream consumers
// (AI prompts, ticketing systems, audit consumers) intact:
//
//   - bool, int, int64, float64, nil — pass through unchanged.
//     These types cannot carry identifier-shaped data; redacting them
//     destroys signal without protecting any sensitive content.
//   - string — routed through s.Value(). Strings may carry ARNs,
//     account IDs, principal names, or other identifiers; the
//     existing per-field opt-in Sanitizer applies.
//   - []string, []any — element-wise sanitization with the same rules.
//   - map[string]any — recursive over values.
//   - any other type — falls back to kernel.Redacted as a conservative
//     default. Better to over-redact an unknown shape than to leak it.
//
// UnsafeValue is intentionally not sanitized: DeriveChanges depends
// on its original primitive value to detect boolean inversions.
func sanitizeActualValue(v any, s kernel.Sanitizer) any {
	switch t := v.(type) {
	case nil:
		return nil
	case bool, int, int64, float64, uint, uint32, uint64:
		return v
	case string:
		return s.Value(t)
	case []string:
		return sanitizeSlice(t, s)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = sanitizeActualValue(e, s)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = sanitizeActualValue(e, s)
		}
		return out
	default:
		// A *named* string type (e.g. kernel.AssetType) reaches the default
		// because the `case string` above matches only the unnamed `string`.
		// Treat any string-KIND value as a string so the result is
		// deterministic regardless of whether ActualValue came straight from
		// the engine (carrying its named type) or round-tripped through the
		// content-addressed assessment cache, which JSON-decodes it back to a
		// plain `string` and erases the named type. Without this, a cache HIT
		// and a cache MISS produced different output for the same value — and
		// a non-sensitive category such as an asset type was needlessly
		// redacted to [SANITIZED] on the (uncached) miss path while a cache
		// hit showed it raw. Routing through s.Value() keeps the per-field
		// identifier sanitizer in effect for named-string identifiers.
		if rv := reflect.ValueOf(v); rv.Kind() == reflect.String {
			return s.Value(rv.String())
		}
		return kernel.Redacted
	}
}

// sanitizeSlice clones and replaces every element using the provided
// sanitizer. Preserves the nil vs empty-slice distinction: nil
// input returns nil, an empty (but non-nil) input returns the same
// empty slice. JSON encoders emit `null` for nil and `[]` for
// empty; the earlier shape always returned `[]T{}`, so a Finding
// whose source slice was deliberately nil silently rendered as `[]`
// instead of `null` and downstream consumers couldn't tell whether
// the field was unset versus empty.
func sanitizeSlice[T ~string](items []T, s kernel.Sanitizer) []T {
	if items == nil {
		return nil
	}
	if len(items) == 0 {
		return items
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
	for i := range fs {
		f := &fs[i]
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
		a.ID = asset.ID(s.ID(string(a.ID)))
		out[i] = a
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
