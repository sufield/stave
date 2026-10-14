package universals

import (
	"time"
)

// UniversalID uniquely identifies a universal compliance formula (e.g., "U26").
type UniversalID string

// Verdict classifies the universal formula evaluation verdict.
type Verdict string

const (
	VerdictHolds    Verdict = "unsat"
	VerdictViolated Verdict = "sat"
	VerdictUnknown  Verdict = "unknown"
	VerdictError    Verdict = "error"
)

// IsHolds reports whether the verdict is unsat (formula holds across all assets).
func (v Verdict) IsHolds() bool {
	return v == VerdictHolds
}

// IsViolated reports whether the verdict is sat (counterexample found).
func (v Verdict) IsViolated() bool {
	return v == VerdictViolated
}

// IsError reports whether the solver failed or encountered an error.
func (v Verdict) IsError() bool {
	return v == VerdictError
}

// IsUnknown reports whether the solver timed out or returned unknown.
func (v Verdict) IsUnknown() bool {
	return v == VerdictUnknown
}

// SolveTimeMs represents an SMT solver execution time in milliseconds.
type SolveTimeMs int64

// Int64 returns the raw integer value in milliseconds.
func (t SolveTimeMs) Int64() int64 {
	return int64(t)
}

// Duration returns the solve time as a time.Duration.
func (t SolveTimeMs) Duration() time.Duration {
	return time.Duration(t) * time.Millisecond
}

// Seconds returns the solve time in fractional seconds.
func (t SolveTimeMs) Seconds() float64 {
	return float64(t) / 1000.0
}

// IsSlow reports whether solving took longer than the provided threshold.
func (t SolveTimeMs) IsSlow(threshold time.Duration) bool {
	return t.Duration() > threshold
}

// Result is the outcome of evaluating one universal formula via Z3.
type Result struct {
	ID          UniversalID `json:"id"`
	Name        string      `json:"name"`
	Verdict     Verdict     `json:"verdict"`
	Holds       bool        `json:"holds"`
	Grounded    int         `json:"grounded"`
	Vacuous     bool        `json:"vacuous,omitempty"`
	Violations  Violations  `json:"violations,omitempty"`
	SolveTimeMs SolveTimeMs `json:"solve_time_ms"`
	Error       string      `json:"error,omitempty"`
}

// Violation is a concrete counterexample from a SAT result.
type Violation struct {
	Constant  string `json:"constant"`
	Predicate string `json:"predicate"`
	Value     bool   `json:"value"`
}

// Violations is a domain collection of Violation counterexamples.
type Violations []Violation

// Len returns the count of violations.
func (v Violations) Len() int {
	return len(v)
}

// ByPredicate returns violations matching the given predicate name.
func (v Violations) ByPredicate(pred string) Violations {
	var out Violations
	for _, item := range v {
		if item.Predicate == pred {
			out = append(out, item)
		}
	}
	return out
}

// ByConstant returns violations matching the given constant name.
func (v Violations) ByConstant(c string) Violations {
	var out Violations
	for _, item := range v {
		if item.Constant == c {
			out = append(out, item)
		}
	}
	return out
}

// Predicates returns the deduplicated list of violated predicate names.
func (v Violations) Predicates() []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range v {
		if !seen[item.Predicate] {
			seen[item.Predicate] = true
			out = append(out, item.Predicate)
		}
	}
	return out
}

// Results is a domain collection of Result evaluation outcomes.
type Results []Result

// Len returns the count of results.
func (r Results) Len() int {
	return len(r)
}

// Holding returns all results where the universal holds.
func (r Results) Holding() Results {
	var out Results
	for _, item := range r {
		if item.Holds {
			out = append(out, item)
		}
	}
	return out
}

// Violated returns all results where the universal was violated.
func (r Results) Violated() Results {
	var out Results
	for _, item := range r {
		if !item.Holds && item.Error == "" {
			out = append(out, item)
		}
	}
	return out
}

// Errored returns all results that encountered an error.
func (r Results) Errored() Results {
	var out Results
	for _, item := range r {
		if item.Error != "" {
			out = append(out, item)
		}
	}
	return out
}

// ByID returns the result with the given universal ID, if found.
func (r Results) ByID(id UniversalID) (Result, bool) {
	for _, item := range r {
		if item.ID == id {
			return item, true
		}
	}
	return Result{}, false
}

// TotalSolveTime returns the sum of solve times across all results.
func (r Results) TotalSolveTime() time.Duration {
	var total time.Duration
	for _, item := range r {
		total += item.SolveTimeMs.Duration()
	}
	return total
}

// Summary aggregates evaluation results across all universals.
type Summary struct {
	Total    int     `json:"total"`
	Hold     int     `json:"hold"`
	Violated int     `json:"violated"`
	Errored  int     `json:"errored"`
	Results  Results `json:"results"`
}

// GroundingMap is the deserialized grounding-map.yaml.
type GroundingMap struct {
	Universals map[UniversalID]UniversalGrounding `yaml:"universals"`
}

// UniversalGrounding defines how to ground observations for one universal.
type UniversalGrounding struct {
	Sort       string                        `yaml:"sort"`
	Predicates []string                      `yaml:"predicates"`
	Groundings map[string]AssetTypeGrounding `yaml:"groundings"`
}

// AssetTypeGrounding maps one asset type's properties to SMT-LIB predicates.
// Keys are predicate names; values are bool constants, ".path" lookups,
// or "!.path" negated lookups. "when" is an optional precondition path.
type AssetTypeGrounding map[string]any
