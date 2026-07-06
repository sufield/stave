package capabilities

import (
	"cmp"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Summary holds catalog-wide aggregate counts for the summary-view header.
//
// SeverityHist is keyed on controldef.Severity — the int-iota enum the control
// CATALOG uses (None..Critical) — NOT pkg/stave.Severity, the 5-level string
// enum used for evaluation FINDINGS. The two are different types with different
// ladders; mixing them miscounts. This type and every caller stay on
// controldef.Severity end to end, so there is no conversion between the two.
//
// The histogram covers controls only. Compound chains carry no projected
// severity (buildChainCaps leaves Capability.Severity empty) and operational
// features have none, so the header reports those as un-rated counts rather
// than folding them into the histogram.
type Summary struct {
	Controls     int                     // total controls loaded
	Services     int                     // distinct services (by control-ID prefix)
	Chains       int                     // compound chains
	Operational  int                     // operational features (the hard-coded list)
	SeverityHist map[policy.Severity]int // per-control severity counts (control groups only)
}

// CatalogSummary computes the catalog-wide aggregates in a single pass over the
// controls. A control with no recognizable CTL.<service> prefix is counted in
// the headline total and the histogram but contributes to no service (it never
// lands in a control group), matching buildControlGroups' skip behaviour.
//
// Named CatalogSummary (not Summarize) because Summarize(version string) in
// this package already returns the build-time AuditCapabilities — a different
// concern.
func CatalogSummary(controls []policy.ControlDefinition, chains []policy.ChainDefinition) Summary {
	services := map[string]struct{}{}
	hist := map[policy.Severity]int{}
	for i := range controls {
		if svc, _ := parseControlID(string(controls[i].ID)); svc != "" {
			services[svc] = struct{}{}
		}
		hist[controls[i].Severity]++
	}
	return Summary{
		Controls:     len(controls),
		Services:     len(services),
		Chains:       len(chains),
		Operational:  len(operationalCaps()),
		SeverityHist: hist,
	}
}

// ServiceRow is one row of the per-service summary table: the service, how many
// (service, category) control groups it has, the total member controls, and the
// highest control severity in the service. MaxSev stays controldef.Severity.
type ServiceRow struct {
	Service  string
	Caps     int
	Controls int
	MaxSev   policy.Severity
	// Sev is the per-severity control breakdown for this service (controldef
	// .Severity), used by the wide summary view. Counts only controls.
	Sev map[policy.Severity]int
}

// ServiceRollup returns one row per service (sorted by service), derived from
// the same (service, category) grouping buildControlGroups uses, so the summary
// table and the grouped catalog never disagree. Severity is computed directly
// on controldef.Severity — no string round-trip, no cross-type mapping.
func ServiceRollup(controls []policy.ControlDefinition) []ServiceRow {
	type groupKey struct{ service, category string }
	groups := map[groupKey]struct{}{}
	rows := map[string]*ServiceRow{}
	for i := range controls {
		svc, cat := parseControlID(string(controls[i].ID))
		if svc == "" {
			continue
		}
		groups[groupKey{svc, cat}] = struct{}{}
		r := rows[svc]
		if r == nil {
			r = &ServiceRow{Service: svc, Sev: map[policy.Severity]int{}}
			rows[svc] = r
		}
		r.Controls++
		r.Sev[controls[i].Severity]++
		if controls[i].Severity > r.MaxSev {
			r.MaxSev = controls[i].Severity
		}
	}
	for k := range groups {
		rows[k.service].Caps++
	}
	out := make([]ServiceRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b ServiceRow) int { return cmp.Compare(a.Service, b.Service) })
	return out
}

// LeafControl is one individual control for the leaf-level drill-down.
type LeafControl struct {
	ID       string
	Name     string
	Service  string
	Category string
	Severity policy.Severity
}

// LeafControls returns the individual controls sorted by (service, category,
// ID), optionally narrowed to one service, one category, and/or one EXACT
// severity. An empty filter string means "all" for that dimension. The severity
// match is exact and case-insensitive via controldef.Severity.Matches — it
// stays on controldef.Severity, no conversion. Chains and operational features
// have no severity and never appear here; the caller documents that a --severity
// filter therefore excludes those un-rated kinds rather than silently dropping
// them.
func LeafControls(controls []policy.ControlDefinition, service, category, severity, taxonomy string) []LeafControl {
	var taxFilter []string
	if taxonomy != "" {
		for t := range strings.SplitSeq(taxonomy, ",") {
			taxFilter = append(taxFilter, strings.TrimSpace(t))
		}
	}
	out := make([]LeafControl, 0, len(controls))
	for i := range controls {
		svc, cat := parseControlID(string(controls[i].ID))
		if svc == "" {
			continue
		}
		if service != "" && !strings.EqualFold(svc, service) {
			continue
		}
		if category != "" && !strings.EqualFold(cat, category) {
			continue
		}
		if severity != "" && !controls[i].Severity.Matches(severity) {
			continue
		}
		if len(taxFilter) > 0 && !hasTaxonomyMatch(controls[i].Taxonomy, taxFilter) {
			continue
		}
		out = append(out, LeafControl{
			ID:       string(controls[i].ID),
			Name:     controls[i].Name,
			Service:  svc,
			Category: cat,
			Severity: controls[i].Severity,
		})
	}
	slices.SortFunc(out, func(a, b LeafControl) int {
		if a.Service != b.Service {
			return cmp.Compare(a.Service, b.Service)
		}
		if a.Category != b.Category {
			return cmp.Compare(a.Category, b.Category)
		}
		return cmp.Compare(a.ID, b.ID)
	})
	return out
}

func hasTaxonomyMatch(tags []kernel.CategoryID, filter []string) bool {
	for _, f := range filter {
		for _, t := range tags {
			if strings.EqualFold(string(t), f) {
				return true
			}
		}
	}
	return false
}
