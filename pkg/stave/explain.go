package stave

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// ErrControlNotFound is returned by [ExplainControl] when the given
// ID is not in the catalog — distinct from a genuine failure (e.g. a
// catalog load error) so callers can offer suggestions for the former
// while surfacing the latter.
var ErrControlNotFound = errors.New("control not found in catalog")

// ControlExplanation is a catalog-only description of one control:
// what it checks, the predicate that fires it, the observation fields
// it reads, and the frameworks it maps to. It is derived purely from
// the embedded catalog — no observations, no evaluation.
//
// Chain membership is intentionally not included: it requires loading
// the chain catalog (a chains directory + capability registry), which
// this offline catalog-query accessor does not do. Omitted rather
// than reported as empty so the absence is not mistaken for "this
// control is in no chains."
type ControlExplanation struct {
	ID              string            `json:"id"`
	Name            string            `json:"name,omitempty"`
	Description     string            `json:"description,omitempty"`
	IntentRationale string            `json:"intent_rationale,omitempty"`
	Severity        string            `json:"severity"`
	AssetTypes      []string          `json:"asset_types,omitempty"`
	Predicate       string            `json:"predicate"`
	RequiredFields  []string          `json:"required_fields,omitempty"`
	Frameworks      map[string]string `json:"frameworks,omitempty"`
	Remediation     string            `json:"remediation,omitempty"`
}

// ExplainControl returns the catalog explanation for one control ID.
// It reads only the embedded builtin catalog, so it is deterministic,
// offline, and safe in hosted mode. Returns an error if the ID is not
// in the catalog.
func ExplainControl(id string) (*ControlExplanation, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("stave.ExplainControl: control id is required")
	}
	controls, err := builtinControls()
	if err != nil {
		return nil, err
	}
	for i := range controls {
		c := &controls[i]
		if string(c.ID) != id {
			continue
		}
		assetTypes := make([]string, 0, len(c.ApplicableAssetTypes))
		for _, at := range c.ApplicableAssetTypes {
			assetTypes = append(assetTypes, string(at))
		}
		var frameworks map[string]string
		if len(c.Compliance) > 0 {
			frameworks = make(map[string]string, len(c.Compliance))
			for fw, req := range c.Compliance {
				frameworks[string(fw)] = string(req)
			}
		}
		remediation := ""
		if c.Remediation != nil {
			remediation = c.Remediation.Description
		}
		return &ControlExplanation{
			ID:              string(c.ID),
			Name:            c.Name,
			Description:     c.Description,
			IntentRationale: c.IntentRationale,
			Severity:        c.Severity.String(),
			AssetTypes:      assetTypes,
			Predicate:       renderPredicate(c.UnsafePredicate),
			RequiredFields:  predicateFields(c.UnsafePredicate),
			Frameworks:      frameworks,
			Remediation:     remediation,
		}, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrControlNotFound, id)
}

// SuggestControlIDs returns up to limit catalog control IDs matching
// query as a case-insensitive substring, sorted. An empty query
// returns the first limit IDs as a sample. Used to build "did you
// mean?" hints for an unknown ID.
func SuggestControlIDs(query string, limit int) []string {
	controls, err := builtinControls()
	if err != nil {
		return nil
	}
	q := strings.ToUpper(strings.TrimSpace(query))
	matches := make([]string, 0, len(controls))
	for i := range controls {
		id := string(controls[i].ID)
		if q == "" || strings.Contains(strings.ToUpper(id), q) {
			matches = append(matches, id)
		}
	}
	slices.Sort(matches)
	if limit > 0 && len(matches) > limit {
		matches = matches[:limit]
	}
	return matches
}

// AssetTypeExamples maps each catalog asset type to one example
// control ID (the lexically smallest, for determinism). Used to guide
// a caller who asked to explain a control without naming one.
func AssetTypeExamples() map[string]string {
	controls, err := builtinControls()
	if err != nil {
		return nil
	}
	ex := map[string]string{}
	for i := range controls {
		id := string(controls[i].ID)
		for _, at := range controls[i].ApplicableAssetTypes {
			k := string(at)
			if cur, ok := ex[k]; !ok || id < cur {
				ex[k] = id
			}
		}
	}
	return ex
}

// renderPredicate flattens a control's unsafe predicate into a
// human-readable boolean expression (field op value, joined by
// AND/OR per the any/all combinator).
func renderPredicate(p policy.UnsafePredicate) string {
	if p.IsEmpty() {
		return "(no predicate)"
	}
	if len(p.All) > 0 {
		return joinRules(p.All, " AND ")
	}
	return joinRules(p.Any, " OR ")
}

func joinRules(rules []policy.PredicateRule, sep string) string {
	parts := make([]string, 0, len(rules))
	for i := range rules {
		parts = append(parts, renderRule(rules[i]))
	}
	return strings.Join(parts, sep)
}

func renderRule(r policy.PredicateRule) string {
	if len(r.All) > 0 {
		return "(" + joinRules(r.All, " AND ") + ")"
	}
	if len(r.Any) > 0 {
		return "(" + joinRules(r.Any, " OR ") + ")"
	}
	value := fmt.Sprintf("%v", r.Value.Raw())
	if !r.ValueFromParam.IsZero() {
		value = "params." + r.ValueFromParam.String()
	}
	return fmt.Sprintf("%s %s %s", r.Field.String(), string(r.Op), value)
}

// predicateFields returns the sorted, deduplicated set of observation
// field paths the predicate reads — the data a snapshot must carry
// for this control to evaluate.
func predicateFields(p policy.UnsafePredicate) []string {
	seen := map[string]struct{}{}
	p.Walk(func(r policy.PredicateRule) {
		if f := r.Field.String(); f != "" {
			seen[f] = struct{}{}
		}
	})
	out := make([]string, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}
