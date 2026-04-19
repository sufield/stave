// Package translation renders predicate-DSL vocabulary
// (ObservationKeys, operators, values) as plain English prose for
// the text output. Consumed by the text writer per
// docs/product/metrics.md § Metric 5. JSON and SARIF outputs retain
// the raw DSL shape — they target downstream tooling rather than
// first-time readers.
package translation

// operatorProse maps each predicate.Operator string to the clause
// verb used in the rendered prose. The phrasing is "must {verb}"
// so the complete clause reads:
//
//	"{observation translation} must {verb} {expected}, but is {observed}"
//
// Inventory matches internal/core/predicate/operators.go at the
// time of the Metric 5 iteration. New operators added to the
// predicate package should land here in the same change.
var operatorProse = map[string]string{
	"eq":                  "equal",
	"ne":                  "not equal",
	"gt":                  "be greater than",
	"lt":                  "be less than",
	"gte":                 "be at least",
	"lte":                 "be at most",
	"missing":             "be missing",
	"present":             "be set",
	"in":                  "be one of",
	"list_empty":          "be empty",
	"contains":            "contain",
	"not_subset_of_field": "not be a subset of",
	"neq_field":           "not equal the value at",
	"not_in_field":        "not be one of the values at",
	"any_match":           "match at least one of",
	"any_in_field":        "overlap with the values at",
}

// OperatorProse returns the plain-language verb phrase for an
// operator, or the raw operator name when the operator is unknown
// (fallback for forward compatibility).
func OperatorProse(op string) string {
	if s, ok := operatorProse[op]; ok {
		return s
	}
	return op
}
