// Package harness orchestrates the per-service Z3 validation
// experiment: it runs Stave's CEL evaluation alongside a service's
// Z3 model on the same fixture corpus, matches the findings, and
// emits an agreement / disagreement report.
//
// CEL is the oracle. The harness never alters Stave's findings;
// the Z3 model is validated against them.
package harness

import (
	"context"
	"time"
)

// ServiceExperiment is the contract every per-service folder
// satisfies. Each service maps its Stave CEL controls to
// equivalent Z3 queries; the harness runs both engines on the
// same fixtures and the comparator reports agreement /
// disagreement.
//
// The interface lives in harness rather than a separate services
// package so the runner avoids an import cycle — each
// services/<name>/ package implements the interface and the
// harness types-checks against it directly.
type ServiceExperiment interface {
	// Name is the AWS service identifier ("s3", "iam", ...).
	Name() string

	// ControlMapping returns Stave control ID → Z3 query name.
	// Several CEL controls may map to the same Z3 query; that
	// "collapse" is the data point CollapseRatio reports.
	ControlMapping() map[string]string

	// RunZ3 compiles the fixture's observations into a Z3 model
	// and emits one Z3Finding per (query, asset) pair.
	RunZ3(ctx context.Context, fixtureDir string) ([]Z3Finding, error)

	// CollapseRatio reports how many CEL controls this service's
	// Z3 model subsumes.
	CollapseRatio() (celControls, z3Queries int)

	// ModelCoverage names the modeled and unmodeled aspects of
	// the service's Z3 model.
	ModelCoverage() ModelCoverage
}

// ComparisonResult classifies a single (asset, control-set)
// comparison between the CEL evaluator and the Z3 model.
type ComparisonResult string

const (
	// AgreeFail — both engines flag the configuration as risky.
	AgreeFail ComparisonResult = "AGREE_FAIL"
	// AgreePass — both engines treat the configuration as safe.
	AgreePass ComparisonResult = "AGREE_PASS"
	// Z3Only — Z3 raised a finding the CEL evaluator did not.
	// Either a real CEL coverage gap (file as a new control) or a
	// Z3 model bug (fix the model).
	Z3Only ComparisonResult = "Z3_ONLY"
	// CELOnly — CEL raised a finding the Z3 model did not.
	// Either a missing constraint in the Z3 model or a property
	// check that intentionally stays as CEL (mark WONTFIX).
	CELOnly ComparisonResult = "CEL_ONLY"
)

// InvestigationStatus tracks the manual review of a disagreement.
type InvestigationStatus string

const (
	StatusPending       InvestigationStatus = "PENDING"
	StatusConfirmedGap  InvestigationStatus = "CONFIRMED_GAP"
	StatusModelBug      InvestigationStatus = "MODEL_BUG"
	StatusFalsePositive InvestigationStatus = "FALSE_POSITIVE"
	StatusWontFix       InvestigationStatus = "WONTFIX"
)

// Z3Finding is the wire shape every ServiceExperiment.RunZ3 emits.
// QueryName is the Z3 query that produced the finding (one Z3
// query may collapse multiple CEL controls); AssetID identifies
// the asset the verdict applies to. Verdict is the CEL-comparable
// "FAIL" / "PASS" projection of the underlying SAT/UNSAT result.
type Z3Finding struct {
	QueryName   string            `json:"query_name"`
	AssetID     string            `json:"asset_id"`
	Result      string            `json:"result"`
	Verdict     string            `json:"verdict"`
	Witness     map[string]string `json:"witness,omitempty"`
	UnsatCore   []string          `json:"unsat_core,omitempty"`
	QueryTimeMs int64             `json:"query_time_ms"`
}

// CELFinding is the trimmed view of one finding parsed from
// `stave apply --format json`. The harness only needs identity
// (asset + control) and the verdict; richer fields can be loaded
// from Stave directly when an investigation digs deeper.
type CELFinding struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
	Verdict   string `json:"verdict"`
}

// FindingComparison records one side-by-side check between CEL and
// Z3 for a single (asset, control-set) pair.
type FindingComparison struct {
	AssetID       string              `json:"asset_id"`
	CELControlID  string              `json:"cel_control_id"`
	Z3QueryName   string              `json:"z3_query_name"`
	CELVerdict    string              `json:"cel_verdict"`
	Z3Verdict     string              `json:"z3_verdict"`
	Result        ComparisonResult    `json:"result"`
	Z3Witness     map[string]string   `json:"z3_witness,omitempty"`
	Z3UnsatCore   []string            `json:"z3_unsat_core,omitempty"`
	Investigation InvestigationStatus `json:"investigation"`
	FixtureDir    string              `json:"fixture_dir"`
}

// AgreementReport aggregates a service's experiment run. The
// agreement / collapse-ratio / model-coverage shape mirrors the
// per-service summary.json structure documented in the harness
// README.
type AgreementReport struct {
	Service          string              `json:"service"`
	ExperimentDate   time.Time           `json:"experiment_date"`
	FixtureCount     int                 `json:"fixture_count"`
	TotalChecks      int                 `json:"total_comparisons"`
	Agreements       int                 `json:"agreements"`
	Z3Only           int                 `json:"z3_only"`
	CELOnly          int                 `json:"cel_only"`
	AgreementRate    float64             `json:"agreement_rate"`
	CollapseRatio    string              `json:"collapse_ratio"`
	CELControlsCount int                 `json:"cel_controls_count"`
	Z3QueriesCount   int                 `json:"z3_queries_count"`
	Comparisons      []FindingComparison `json:"comparisons"`
	SkippedFixtures  []SkippedFixture    `json:"skipped_fixtures,omitempty"`
	ModelCoverage    ModelCoverage       `json:"model_coverage"`
}

// SkippedFixture records a fixture the harness could not score:
// either Stave's CEL evaluator rejected it (intentional bad-schema
// test cases live in the corpus), or the per-service Z3 model
// returned an error. The skip is logged rather than fatal so a
// single broken fixture does not gate the whole run.
type SkippedFixture struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Error  string `json:"error,omitempty"`
}

// ModelCoverage names the modeled and unmodeled aspects of the
// service's Z3 model. Honest accounting matters: a UNSAT verdict
// is sound only relative to the modeled fragment.
type ModelCoverage struct {
	Modeled           []string `json:"modeled"`
	NotModeled        []string `json:"not_modeled"`
	KnownLimitations  []string `json:"known_limitations,omitempty"`
}

// IsAgreement reports whether the comparison's result is one of
// the agreement classes (BothFail / BothPass).
func (c FindingComparison) IsAgreement() bool {
	return c.Result == AgreeFail || c.Result == AgreePass
}
