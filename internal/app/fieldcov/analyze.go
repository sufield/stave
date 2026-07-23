// Package fieldcov analyzes observation field coverage against control
// predicates. It detects controls that cannot evaluate because required
// fields are missing from snapshots, and identifies silent-risk controls
// where missing fields could produce false PASS verdicts.
package fieldcov

import (
	"cmp"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
	"github.com/sufield/stave/internal/util/sets"
)

// Classification describes a control's evaluability status.
type Classification string

const (
	// Evaluable means all referenced fields are present.
	Evaluable Classification = "EVALUABLE"
	// Incomplete means some fields are missing — INCOMPLETE verdict expected.
	Incomplete Classification = "INCOMPLETE"
	// SilentRisk means missing fields could produce a false PASS.
	SilentRisk Classification = "SILENT_RISK"
	// NoAssets means no assets of the required type exist in the snapshot.
	NoAssets Classification = "NO_ASSETS"
)

// ControlResult holds the coverage analysis for a single control.
type ControlResult struct {
	ControlID      string         `json:"control_id"`
	Severity       string         `json:"severity"`
	Classification Classification `json:"classification"`
	MissingFields  []string       `json:"missing_fields,omitempty"`
	AssetType      string         `json:"asset_type,omitempty"`
	Frameworks     []string       `json:"compliance_frameworks,omitempty"`
	Risk           string         `json:"risk,omitempty"`
}

// ShoppingItem is a missing field grouped by asset type.
type ShoppingItem struct {
	Field       string   `json:"field"`
	RequiredBy  []string `json:"required_by"`
	MaxSeverity string   `json:"max_severity"`
}

// FrameworkCoverage holds coverage stats for a compliance framework.
type FrameworkCoverage struct {
	Evaluable   int     `json:"evaluable"`
	Total       int     `json:"total"`
	Incomplete  int     `json:"incomplete"`
	SilentRisk  int     `json:"silent_risk"`
	CoveragePct float64 `json:"coverage_pct"`
}

// Report is the full coverage analysis output.
type Report struct {
	Snapshot          string                        `json:"snapshot"`
	GeneratedAt       string                        `json:"generated_at"`
	Summary           Summary                       `json:"summary"`
	SilentRisk        []ControlResult               `json:"silent_risk"`
	IncompleteResults []ControlResult               `json:"incomplete"`
	ShoppingList      map[string][]ShoppingItem     `json:"extractor_shopping_list"`
	FrameworkCoverage map[string]*FrameworkCoverage `json:"framework_coverage"`
}

// Summary holds aggregate counts.
type Summary struct {
	Total      int `json:"total"`
	Evaluable  int `json:"evaluable"`
	Incomplete int `json:"incomplete"`
	SilentRisk int `json:"silent_risk"`
	NoAssets   int `json:"no_assets"`
}

// AnalyzeInput holds the data needed for coverage analysis.
type AnalyzeInput struct {
	SnapshotPath string
	GeneratedAt  string
	Controls     []policy.ControlDefinition
	Snapshots    []asset.Snapshot
}

// Analyze performs coverage analysis of controls against snapshot fields.
func Analyze(input AnalyzeInput) *Report {
	// Build a set of all property paths present across all assets.
	presentFields := collectPresentFields(input.Snapshots)
	presentAssetTypes := collectPresentAssetTypes(input.Snapshots)

	var results []ControlResult
	for i := range input.Controls {
		ctl := &input.Controls[i]
		result := classifyControl(ctl, presentFields, presentAssetTypes)
		results = append(results, result)
	}

	return buildReport(input, results)
}

// collectPresentFields walks all assets in all snapshots and returns
// the set of property field paths that exist.
func collectPresentFields(snapshots []asset.Snapshot) map[string]struct{} {
	fields := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			walkProperties("properties", a.Properties, fields)
		}
	}
	return fields
}

// collectPresentAssetTypes walks all assets in all snapshots and returns
// the set of asset types that exist.
func collectPresentAssetTypes(snapshots []asset.Snapshot) map[string]struct{} {
	types := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, a := range snap.Assets {
			types[string(a.Type)] = struct{}{}
		}
	}
	return types
}

// walkProperties recursively walks a nested map and collects all leaf paths.
func walkProperties(prefix string, m map[string]any, out map[string]struct{}) {
	for k, v := range m {
		path := prefix + "." + k
		out[path] = struct{}{}
		if nested, ok := v.(map[string]any); ok {
			walkProperties(path, nested, out)
		}
	}
}

// classifyControl determines coverage classification for a single control.
func classifyControl(ctl *policy.ControlDefinition, presentFields map[string]struct{}, presentAssetTypes map[string]struct{}) ControlResult {
	result := ControlResult{
		ControlID:  string(ctl.ID),
		Severity:   ctl.Severity.String(),
		Frameworks: extractFrameworks(ctl),
	}

	if presentAssetTypes != nil && len(ctl.ApplicableAssetTypes) > 0 {
		hasAsset := false
		for _, at := range ctl.ApplicableAssetTypes {
			if _, ok := presentAssetTypes[string(at)]; ok {
				hasAsset = true
				break
			}
		}
		if !hasAsset {
			result.Classification = NoAssets
			result.AssetType = string(ctl.ApplicableAssetTypes[0])
			return result
		}
	}

	pred := &ctl.UnsafePredicate
	if len(pred.Any) == 0 && len(pred.All) == 0 {
		// Evaluable = required fields are present. Does NOT assert values
		// are correct — value correctness is the evaluation engine's job.
		result.Classification = Evaluable
		return result
	}

	// Extract all field references from the predicate.
	refs := extractFieldRefs(pred)
	if len(refs) == 0 {
		result.Classification = Evaluable
		return result
	}

	// Check which fields are missing.
	var missing []string
	var silentRiskFields []string
	for _, ref := range refs {
		if !fieldPresent(ref.path, presentFields) {
			missing = append(missing, ref.path)
			if ref.silentRisk {
				silentRiskFields = append(silentRiskFields, ref.path)
			}
		}
	}

	if len(missing) == 0 {
		result.Classification = Evaluable
		return result
	}

	result.MissingFields = missing
	if len(silentRiskFields) > 0 {
		result.Classification = SilentRisk
		result.Risk = "predicate checks absent field without has() guard — may produce false PASS"
	} else {
		result.Classification = Incomplete
	}

	return result
}

// fieldRef is a field reference extracted from a predicate.
type fieldRef struct {
	path       string
	silentRisk bool // true if missing field could cause false PASS
}

// extractFieldRefs walks a predicate tree and returns all field references.
func extractFieldRefs(pred *policy.UnsafePredicate) []fieldRef {
	var refs []fieldRef
	for i := range pred.Any {
		refs = collectRuleRefs(&pred.Any[i], refs)
	}
	for i := range pred.All {
		refs = collectRuleRefs(&pred.All[i], refs)
	}

	// Deduplicate by path.
	seen := sets.New[string]()
	var deduped []fieldRef
	for _, r := range refs {
		if !seen.Contains(r.path) {
			seen.Add(r.path)
			deduped = append(deduped, r)
		}
	}
	return deduped
}

func collectRuleRefs(rule *policy.PredicateRule, refs []fieldRef) []fieldRef {
	for i := range rule.Any {
		refs = collectRuleRefs(&rule.Any[i], refs)
	}
	for i := range rule.All {
		refs = collectRuleRefs(&rule.All[i], refs)
	}

	// any_match / any_identity_match nest a sub-predicate in Value.
	// Without recursing into it, fields inside the nested predicate
	// are invisible to coverage analysis.
	if rule.Op == predicate.OpAnyMatch || rule.Op == predicate.OpAnyIdentityMatch {
		parent := rule.Field.String()
		if parent == "" && rule.Op == predicate.OpAnyIdentityMatch {
			parent = "identities"
		}
		if parent != "" {
			refs = append(refs, fieldRef{path: parent, silentRisk: true})
			refs = collectNestedValueRefs(parent, rule.Value.Raw(), refs)
		}
		return refs
	}

	// Cross-field operators compare rule.Field against a second field
	// whose path is in rule.Value. When value_from_param is set the
	// comparison target is a parameter, not a field — skip extraction.
	if isCrossFieldOp(rule.Op) && rule.ValueFromParam == "" {
		if other, ok := rule.Value.Raw().(string); ok && other != "" {
			refs = append(refs, fieldRef{path: other, silentRisk: true})
		}
	}

	if rule.Field.IsZero() {
		return refs
	}

	path := rule.Field.String()
	// A field is silent-risk if the operator is eq/ne/gt/lt/etc.
	// (value comparison on potentially absent field).
	// The "missing" and "present" operators are explicit checks
	// — they handle absence correctly and are not silent-risk.
	silentRisk := rule.Op != predicate.OpMissing && rule.Op != predicate.OpPresent

	return append(refs, fieldRef{path: path, silentRisk: silentRisk})
}

// collectNestedValueRefs extracts field references from an any_match
// nested predicate value. Handles both typed (*UnsafePredicate) from
// tests and raw (map[string]any) from YAML loading.
func collectNestedValueRefs(parentPath string, val any, refs []fieldRef) []fieldRef {
	switch v := val.(type) {
	case *policy.UnsafePredicate:
		if v != nil {
			refs = collectNestedPredRefs(parentPath, v, refs)
		}
	case policy.UnsafePredicate:
		refs = collectNestedPredRefs(parentPath, &v, refs)
	case map[string]any:
		refs = collectNestedMapRefs(parentPath, v, refs)
	}
	return refs
}

func collectNestedPredRefs(parentPath string, pred *policy.UnsafePredicate, refs []fieldRef) []fieldRef {
	for i := range pred.Any {
		refs = collectNestedRuleRef(parentPath, &pred.Any[i], refs)
	}
	for i := range pred.All {
		refs = collectNestedRuleRef(parentPath, &pred.All[i], refs)
	}
	return refs
}

func collectNestedRuleRef(parentPath string, rule *policy.PredicateRule, refs []fieldRef) []fieldRef {
	for i := range rule.Any {
		refs = collectNestedRuleRef(parentPath, &rule.Any[i], refs)
	}
	for i := range rule.All {
		refs = collectNestedRuleRef(parentPath, &rule.All[i], refs)
	}
	if rule.Field.IsZero() {
		return refs
	}
	path := parentPath + "." + rule.Field.String()
	silentRisk := rule.Op != predicate.OpMissing && rule.Op != predicate.OpPresent
	return append(refs, fieldRef{path: path, silentRisk: silentRisk})
}

// collectNestedMapRefs walks a raw map[string]any nested predicate
// (the shape YAML produces before typed parsing).
func collectNestedMapRefs(parentPath string, m map[string]any, refs []fieldRef) []fieldRef {
	for _, key := range [2]string{"any", "all"} {
		list, ok := m[key]
		if !ok {
			continue
		}
		items, ok := list.([]any)
		if !ok {
			continue
		}
		for _, item := range items {
			ruleMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			refs = collectNestedMapRefs(parentPath, ruleMap, refs)
		}
	}
	fieldStr, _ := m["field"].(string)
	if fieldStr == "" {
		return refs
	}
	path := parentPath + "." + fieldStr
	op, _ := m["op"].(string)
	silentRisk := op != "missing" && op != "present"
	return append(refs, fieldRef{path: path, silentRisk: silentRisk})
}

func isCrossFieldOp(op predicate.Operator) bool {
	switch op {
	case predicate.OpNotSubsetOfField, predicate.OpNeqField,
		predicate.OpNotInField, predicate.OpAnyInField:
		return true
	}
	return false
}

// fieldPresent checks if a field path exists in the collected fields.
// collectPresentFields records every key at every nesting level, so a field
// is present only if its exact path was collected. A scalar value at a parent
// path (e.g. "properties.encryption") must NOT satisfy presence of a deeper
// child path (e.g. "properties.encryption.enabled") — that leaf was never
// collected and the deeper field is genuinely missing.
func fieldPresent(path string, fields map[string]struct{}) bool {
	_, ok := fields[path]
	return ok
}

// extractFrameworks returns compliance framework names from a control.
func extractFrameworks(ctl *policy.ControlDefinition) []string {
	if len(ctl.Compliance) == 0 {
		return nil
	}
	var fws []string
	for fw := range ctl.Compliance {
		fws = append(fws, string(fw))
	}
	slices.Sort(fws)
	return fws
}

func buildReport(input AnalyzeInput, results []ControlResult) *Report {
	report := &Report{
		Snapshot:          input.SnapshotPath,
		GeneratedAt:       input.GeneratedAt,
		ShoppingList:      make(map[string][]ShoppingItem),
		FrameworkCoverage: make(map[string]*FrameworkCoverage),
	}

	var silentRisk, incomplete []ControlResult
	for i := range results {
		r := &results[i]
		switch r.Classification {
		case Evaluable:
			report.Summary.Evaluable++
		case Incomplete:
			report.Summary.Incomplete++
			incomplete = append(incomplete, *r)
		case SilentRisk:
			report.Summary.SilentRisk++
			silentRisk = append(silentRisk, *r)
		case NoAssets:
			report.Summary.NoAssets++
		}
		report.Summary.Total++

		// Framework coverage.
		for _, fw := range r.Frameworks {
			fc, ok := report.FrameworkCoverage[fw]
			if !ok {
				fc = &FrameworkCoverage{}
				report.FrameworkCoverage[fw] = fc
			}
			fc.Total++
			switch r.Classification {
			case Evaluable:
				fc.Evaluable++
			case Incomplete:
				fc.Incomplete++
			case SilentRisk:
				fc.SilentRisk++
			}
		}
	}

	// Compute coverage percentages.
	for _, fc := range report.FrameworkCoverage {
		if fc.Total > 0 {
			fc.CoveragePct = float64(fc.Evaluable) / float64(fc.Total) * 100
		}
	}

	// Sort by severity (critical first) and ControlID as tie-breaker.
	sevOrder := policy.SeverityOrderOf
	slices.SortFunc(silentRisk, func(a, b ControlResult) int {
		if sa, sb := sevOrder(a.Severity), sevOrder(b.Severity); sa != sb {
			return cmp.Compare(sa, sb)
		}
		return cmp.Compare(a.ControlID, b.ControlID)
	})
	slices.SortFunc(incomplete, func(a, b ControlResult) int {
		if sa, sb := sevOrder(a.Severity), sevOrder(b.Severity); sa != sb {
			return cmp.Compare(sa, sb)
		}
		return cmp.Compare(a.ControlID, b.ControlID)
	})

	report.SilentRisk = silentRisk
	report.IncompleteResults = incomplete

	// Build shopping list grouped by asset type — use first field prefix.
	fieldToControls := make(map[string][]string)
	fieldToSeverity := make(map[string]string)
	combined := make([]ControlResult, 0, len(silentRisk)+len(incomplete))
	combined = append(combined, silentRisk...)
	combined = append(combined, incomplete...)
	for i := range combined {
		r := &combined[i]
		for _, f := range r.MissingFields {
			fieldToControls[f] = append(fieldToControls[f], r.ControlID)
			if sevOrder(r.Severity) < sevOrder(fieldToSeverity[f]) || fieldToSeverity[f] == "" {
				fieldToSeverity[f] = r.Severity
			}
		}
	}

	// Prefer control-declared asset types over the heuristic.
	controlAssetType := make(map[string]string, len(input.Controls))
	for i := range input.Controls {
		if len(input.Controls[i].ApplicableAssetTypes) > 0 {
			controlAssetType[string(input.Controls[i].ID)] = string(input.Controls[i].ApplicableAssetTypes[0])
		}
	}

	for field, ctls := range fieldToControls {
		assetType := ""
		for _, ctlID := range ctls {
			if at, ok := controlAssetType[ctlID]; ok {
				assetType = at
				break
			}
		}
		if assetType == "" {
			assetType = deriveAssetType(field)
		}
		report.ShoppingList[assetType] = append(report.ShoppingList[assetType], ShoppingItem{
			Field:       field,
			RequiredBy:  ctls,
			MaxSeverity: fieldToSeverity[field],
		})
	}

	// Sort shopping list items by severity, with Field as tie-breaker.
	for at := range report.ShoppingList {
		items := report.ShoppingList[at]
		slices.SortFunc(items, func(a, b ShoppingItem) int {
			if sa, sb := sevOrder(a.MaxSeverity), sevOrder(b.MaxSeverity); sa != sb {
				return cmp.Compare(sa, sb)
			}
			return cmp.Compare(a.Field, b.Field)
		})
		report.ShoppingList[at] = items
	}

	return report
}

// deriveAssetType guesses asset type from field path prefix.
func deriveAssetType(field string) string {
	_, rest, found := strings.Cut(field, ".")
	if !found {
		return "unknown"
	}
	part1, _, _ := strings.Cut(rest, ".")
	if part1 == "" {
		return "unknown"
	}
	// properties.storage → s3, properties.database → rds, etc.
	switch part1 {
	case "storage":
		return "s3_bucket"
	case "database":
		return "rds_instance"
	case "compute":
		return "ec2_instance"
	case "filesystem":
		return "efs_filesystem"
	case "cdn":
		return "cloudfront_distribution"
	case "container":
		return "ecs_service"
	case "identity":
		return "iam_or_cognito"
	case "network":
		return "vpc"
	case "threat_detection":
		return "guardduty"
	case "monitoring":
		return "cloudwatch"
	case "trail":
		return "cloudtrail"
	case "k8s", "logging", "addons", "encryption", "endpoint", "nodegroup":
		return "eks_cluster"
	default:
		return part1
	}
}
