package translation

import (
	"fmt"
	"strings"
)

// FieldRegistry maps observation field paths (e.g.
// "storage.access.has_wildcard_principal") to their plain-language
// one-liner. A nil or missing entry is a signal to fall back to the
// raw DSL rendering.
type FieldRegistry map[string]string

// Lookup returns (prose, ok). Callers fall back to the raw field
// path when ok is false.
func (r FieldRegistry) Lookup(key string) (string, bool) {
	if r == nil {
		return "", false
	}
	v, ok := r[key]
	return v, ok
}

// Clause is the translator's input — the same triple
// (observation, operator, expected vs observed) that
// evaluation.MatchedClause carries, decoupled from the evaluation
// package to keep this package free of core-layer deps.
type Clause struct {
	ObservationKey string
	Operator       string
	ExpectedValue  any
	ObservedValue  any
}

// ClauseRole classifies a matched predicate clause by semantic role.
// Gate clauses select which assets the predicate applies to (asset-
// class filters, parameterized constraints); they are not violations.
// UnsafeMatch clauses identify the unsafe condition the predicate
// detected. Renderers can use the role to surface clauses under
// different section headers so readers can tell which clauses point
// at the violation and which are predicate machinery.
type ClauseRole int

const (
	// RoleUnsafeMatch is the clause that identifies the unsafe state
	// the predicate detected (the violation signal).
	RoleUnsafeMatch ClauseRole = iota
	// RoleGate is a clause that selects which assets the predicate
	// applies to: asset-class discriminator (storage.kind, identity.kind,
	// etc.) or parameterized constraint (a top-level field that the
	// control's params drive, e.g., protected_prefix). Not a violation.
	RoleGate
)

// discriminatorKeys mirrors the Issues-dedup discriminator list at
// internal/core/evaluation/issue.go:68. Fields here are kind-class
// gates that limit which asset shapes a predicate evaluates against.
// Kept in sync by convention; new entries on either side land on the
// other side in the same iteration.
var discriminatorKeys = map[string]struct{}{
	"storage.kind":      {},
	"compute.kind":      {},
	"identity.kind":     {},
	"cryptography.kind": {},
	"container.kind":    {},
	"backup.kind":       {},
}

// ClassifyClause returns the clause's semantic role from its
// observation key alone. Two patterns identify a gate:
//
//   - Kind-discriminator key (storage.kind, compute.kind, etc.) —
//     limits the predicate to a specific asset class.
//   - Top-level key (no '.') — typically a control-parameter-derived
//     constraint such as protected_prefix or exposure_source.
//
// Every other clause is treated as RoleUnsafeMatch. The classification
// derives from existing structured data; no contract or trace
// extension is required.
func ClassifyClause(observationKey string) ClauseRole {
	if _, ok := discriminatorKeys[observationKey]; ok {
		return RoleGate
	}
	if !strings.Contains(observationKey, ".") {
		return RoleGate
	}
	return RoleUnsafeMatch
}

// RenderClause produces one line of plain English prose for a matched
// predicate clause. See docs/product/metrics.md § Metric 5.
//
// The shape states the observation directly without "must equal X,
// but is X" expectation framing. The match relationship is implicit:
// every clause in a finding's reasoning_trace fired (the predicate
// matched). Section context (Reasoning vs Scope) tells the reader
// whether the observation is the unsafe condition or scope-defining
// metadata; see ClassifyClause.
//
// Per-operator output:
//
//   - eq:                 "{field} = {observed}"
//   - missing (matched):  "{field} is not set"
//   - present (matched):  "{field} is set (observed: {observed})"
//   - all others:         "{field} {op-prose} {expected} (observed: {observed})"
//
// Edge-case rules:
//   - Unknown ObservationKey: falls back to the raw key as field
//     prose. Output stays readable.
//   - Unknown operator: falls back to the raw op string in place of
//     the verb phrase.
func RenderClause(c Clause, registry FieldRegistry) string {
	fieldProse, found := registry.Lookup(c.ObservationKey)
	if !found {
		fieldProse = c.ObservationKey
	}

	switch c.Operator {
	case "eq":
		return fieldProse + " = " + formatValue(c.ObservedValue)
	case "missing":
		if c.ObservedValue == nil {
			return fieldProse + " is not set"
		}
		return fieldProse + " is not set (observed: " + formatValue(c.ObservedValue) + ")"
	case "present":
		if c.ObservedValue == nil {
			return fieldProse + " is set"
		}
		return fieldProse + " is set (observed: " + formatValue(c.ObservedValue) + ")"
	}

	return fmt.Sprintf("%s %s %s (observed: %s)",
		fieldProse,
		OperatorProse(c.Operator),
		formatValue(c.ExpectedValue),
		formatValue(c.ObservedValue),
	)
}

// formatValue returns a reader-friendly literal for a value. Bools
// render as "true"/"false"; strings are quoted; nil renders as "not
// set"; slices collapse to JSON-ish `[a, b]` form.
func formatValue(v any) string {
	if v == nil {
		return "not set"
	}
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		if t == "" {
			return "an empty string"
		}
		return "\"" + t + "\""
	case []any:
		parts := make([]string, len(t))
		for i, it := range t {
			parts[i] = formatValue(it)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		parts := make([]string, len(t))
		for i, it := range t {
			parts[i] = "\"" + it + "\""
		}
		return "[" + strings.Join(parts, ", ") + "]"
	default:
		return fmt.Sprint(t)
	}
}
