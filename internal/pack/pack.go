// Package pack defines concern packs: named, cross-cutting groupings of
// controls (e.g. "entropy", "quick") plus a requirements manifest describing
// the AWS API calls and observation signals the pack needs. A pack is distinct
// from a compliance --profile (framework evaluation) and from a filesystem
// domain (-i path): membership is resolved by explicit control IDs, ID-glob
// patterns, and a minimum severity — using the existing CTL.<DOMAIN>.<CATEGORY>
// ID convention, so no per-control schema change is needed.
//
// The logic is pure — it holds no Stave evaluation types and resolves against a
// minimal []ControlMeta — so it unit-tests without the engine.
package pack

import (
	"path"
	"slices"
	"sort"
	"strings"
)

// Pack is a named concern grouping plus its data requirements.
type Pack struct {
	Name         string       `yaml:"name"`
	Title        string       `yaml:"title"`
	Description  string       `yaml:"description"`
	Controls     Selector     `yaml:"controls"`
	Requirements Requirements `yaml:"requirements"`
}

// Selector picks controls into the pack: the union of explicit IDs, ID-glob
// patterns (filepath.Match syntax; IDs contain no '/', so '*' spans '.'), and —
// if MinSeverity is set — every control at or above that severity. Limit caps
// the result (highest severity first, then ID), 0 = no cap.
type Selector struct {
	IDs         []string `yaml:"ids"`
	IDPatterns  []string `yaml:"id_patterns"`
	MinSeverity string   `yaml:"min_severity"`
	Limit       int      `yaml:"limit"`
}

// Requirements is the manifest: what data a snapshot must carry for this pack.
type Requirements struct {
	AWSAPICalls        []ServiceCalls `yaml:"aws_api_calls" json:"aws_api_calls"`
	ObservationSignals []string       `yaml:"observation_signals" json:"observation_signals"`
	MinimumPermissions string         `yaml:"minimum_permissions" json:"minimum_permissions"`
}

// ServiceCalls groups the AWS CLI calls for one service.
type ServiceCalls struct {
	Service string   `yaml:"service" json:"service"`
	Calls   []string `yaml:"calls" json:"calls"`
	Notes   string   `yaml:"notes" json:"notes,omitempty"`
}

// ControlMeta is the minimal control info pack resolution needs.
type ControlMeta struct {
	ID       string
	Severity string
}

// severityRank orders severities high→low; unknown sorts last.
var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

// Resolve returns the sorted, deduplicated set of catalog control IDs this pack
// selects. Explicit IDs that don't exist in the catalog are dropped (a pack may
// name controls not yet built); use Missing to surface them.
func (p Pack) Resolve(catalog []ControlMeta) []string {
	want := map[string]bool{}
	for _, id := range p.Controls.IDs {
		want[id] = true
	}
	minRank := 0
	if p.Controls.MinSeverity != "" {
		minRank = severityRank[strings.ToLower(p.Controls.MinSeverity)]
	}
	matched := map[string]string{} // id -> severity
	for _, c := range catalog {
		hit := want[c.ID]
		if !hit {
			for _, pat := range p.Controls.IDPatterns {
				if ok, _ := path.Match(pat, c.ID); ok {
					hit = true
					break
				}
			}
		}
		if !hit && minRank > 0 && severityRank[strings.ToLower(c.Severity)] >= minRank {
			hit = true
		}
		if hit {
			matched[c.ID] = c.Severity
		}
	}
	out := make([]string, 0, len(matched))
	for id := range matched {
		out = append(out, id)
	}
	// Highest severity first, then ID, so Limit keeps the most impactful.
	sort.Slice(out, func(i, j int) bool {
		ri, rj := severityRank[strings.ToLower(matched[out[i]])], severityRank[strings.ToLower(matched[out[j]])]
		if ri != rj {
			return ri > rj
		}
		return out[i] < out[j]
	})
	if p.Controls.Limit > 0 && len(out) > p.Controls.Limit {
		out = out[:p.Controls.Limit]
	}
	slices.Sort(out)
	return out
}

// Missing returns explicitly-listed IDs that are not present in the catalog.
func (p Pack) Missing(catalog []ControlMeta) []string {
	have := make(map[string]bool, len(catalog))
	for _, c := range catalog {
		have[c.ID] = true
	}
	var miss []string
	for _, id := range p.Controls.IDs {
		if !have[id] {
			miss = append(miss, id)
		}
	}
	slices.Sort(miss)
	return miss
}
