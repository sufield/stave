package universals

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

// Result is the outcome of evaluating one universal formula via Z3.
type Result struct {
	ID          UniversalID `json:"id"`
	Name        string      `json:"name"`
	Verdict     Verdict     `json:"verdict"`
	Holds       bool        `json:"holds"`
	Grounded    int         `json:"grounded"`
	Vacuous     bool        `json:"vacuous,omitempty"`
	Violations  []Violation `json:"violations,omitempty"`
	SolveTimeMs int64       `json:"solve_time_ms"`
	Error       string      `json:"error,omitempty"`
}

// Violation is a concrete counterexample from a SAT result.
type Violation struct {
	Constant  string `json:"constant"`
	Predicate string `json:"predicate"`
	Value     bool   `json:"value"`
}

// Summary aggregates evaluation results across all universals.
type Summary struct {
	Total    int      `json:"total"`
	Hold     int      `json:"hold"`
	Violated int      `json:"violated"`
	Errored  int      `json:"errored"`
	Results  []Result `json:"results"`
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
