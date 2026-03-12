package evaluation

import (
	"cmp"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
)

// ConfidenceLevel quantifies the certainty of an evaluation result.
type ConfidenceLevel string

const (
	ConfidenceHigh         ConfidenceLevel = "high"
	ConfidenceMedium       ConfidenceLevel = "medium"
	ConfidenceLow          ConfidenceLevel = "low"
	ConfidenceInconclusive ConfidenceLevel = "inconclusive"
)

// confidenceRange defines thresholds for classifying evaluation confidence.
type confidenceRange struct {
	multiplier int
	level      ConfidenceLevel
}

var confidenceThresholds = []confidenceRange{
	{4, ConfidenceHigh},   // maxGap <= 25% of window
	{2, ConfidenceMedium}, // maxGap <= 50% of window
}

// DeriveConfidenceLevel classifies confidence based on the largest observation gap
// relative to the required evaluation window.
func DeriveConfidenceLevel(maxGap, requiredWindow time.Duration) ConfidenceLevel {
	if requiredWindow <= 0 {
		return ConfidenceInconclusive
	}

	for _, t := range confidenceThresholds {
		if maxGap*time.Duration(t.multiplier) <= requiredWindow {
			return t.level
		}
	}
	return ConfidenceLow
}

// SafetyStatus classifies the high-level security posture based on evaluation results.
type SafetyStatus string

const (
	StatusSafe       SafetyStatus = "SAFE"
	StatusBorderline SafetyStatus = "BORDERLINE"
	StatusUnsafe     SafetyStatus = "UNSAFE"
)

// ClassifySafetyStatus derives posture from violation counts and approaching risks.
func ClassifySafetyStatus(violations int, upcoming risk.Items) SafetyStatus {
	if violations > 0 {
		return StatusUnsafe
	}
	if upcoming.HasAnyRisk() {
		return StatusBorderline
	}
	return StatusSafe
}

// Decision represents the final outcome of a control check against a resource.
type Decision string

const (
	DecisionViolation     Decision = "VIOLATION"
	DecisionPass          Decision = "PASS"
	DecisionInconclusive  Decision = "INCONCLUSIVE"
	DecisionNotApplicable Decision = "NOT_APPLICABLE"
	DecisionSkipped       Decision = "SKIPPED"
)

// Row captures the granular result for a single control/asset pairing.
type Row struct {
	ControlID   kernel.ControlID `json:"control_id"`
	AssetID     asset.ID         `json:"asset_id"`
	AssetType   kernel.AssetType `json:"asset_type"`
	AssetDomain string           `json:"asset_domain"`
	Decision    Decision         `json:"decision"`
	Confidence  ConfidenceLevel  `json:"confidence"`
	Evidence    *Evidence        `json:"evidence,omitempty"`
	WhyNow      string           `json:"why_now,omitempty"`
	Reason      string           `json:"reason,omitempty"` // populated for SKIPPED/INCONCLUSIVE
}

// MarkInconclusive shifts a row to an inconclusive state with a specific explanation.
func (r *Row) MarkInconclusive(reason string) {
	if r == nil {
		return
	}
	r.Decision = DecisionInconclusive
	r.Confidence = ConfidenceInconclusive
	r.Reason = reason
}

// Summary provides high-level metrics for an evaluation run.
type Summary struct {
	AssetsEvaluated int `json:"assets_evaluated"`
	AttackSurface   int `json:"attack_surface"`
	Violations      int `json:"violations"`
}

// SkippedControl identifies a control that was ignored during the run.
type SkippedControl struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// Result is the root aggregate of an evaluation execution.
type Result struct {
	Run                RunInfo              `json:"run"`
	Summary            Summary              `json:"summary"`
	Findings           []Finding            `json:"findings"`
	SuppressedFindings []SuppressedFinding  `json:"suppressed_findings,omitempty"`
	Skipped            []SkippedControl     `json:"skipped,omitempty"`
	SkippedAssets      []asset.SkippedAsset `json:"skipped_assets,omitempty"`
	Metadata           Metadata             `json:"-"`
	Rows               []Row                `json:"rows,omitempty"` // populated if --explain is used
}

// FindFinding retrieves a finding for a specific control/asset pair, returning nil if not found.
func (r *Result) FindFinding(ctlID kernel.ControlID, astID asset.ID) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ControlID == ctlID && r.Findings[i].AssetID == astID {
			return &r.Findings[i]
		}
	}
	return nil
}

// DomainCount represents the number of violations in a specific business domain.
type DomainCount struct {
	Domain string
	Count  int
}

// GroupViolationsByDomain aggregates violation rows into sorted counts by asset domain.
func GroupViolationsByDomain(rows []Row) []DomainCount {
	if len(rows) == 0 {
		return nil
	}

	counts := make(map[string]int, len(rows)/10)
	for i := range rows {
		if rows[i].Decision != DecisionViolation {
			continue
		}

		d := strings.ToLower(strings.TrimSpace(rows[i].AssetDomain))
		if d == "" {
			d = "unknown"
		}
		counts[d]++
	}

	res := make([]DomainCount, 0, len(counts))
	for d, c := range counts {
		res = append(res, DomainCount{Domain: d, Count: c})
	}

	slices.SortFunc(res, func(a, b DomainCount) int {
		return cmp.Compare(a.Domain, b.Domain)
	})

	return res
}
