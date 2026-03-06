package evaluation

import (
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
)

// ConfidenceLevel represents the confidence in an evaluation decision.
type ConfidenceLevel string

const (
	ConfidenceHigh         ConfidenceLevel = "high"
	ConfidenceMedium       ConfidenceLevel = "medium"
	ConfidenceLow          ConfidenceLevel = "low"
	ConfidenceInconclusive ConfidenceLevel = "inconclusive"
)

// confidenceRange maps a gap-to-window ratio threshold to a confidence level.
// Multiplication form (maxGap*N <= window) keeps integer precision.
type confidenceRange struct {
	multiplier int
	level      ConfidenceLevel
}

var confidenceRanges = []confidenceRange{
	{4, ConfidenceHigh},   // maxGap <= 25% of window
	{2, ConfidenceMedium}, // maxGap <= 50% of window
}

// DeriveConfidenceLevel classifies confidence based on MaxGap relative to the required window.
//
//	gap <= 25% window -> high
//	gap <= 50% window -> medium
//	gap >  50% window -> low
func DeriveConfidenceLevel(maxGap, requiredWindow time.Duration) ConfidenceLevel {
	if requiredWindow <= 0 {
		return ConfidenceInconclusive
	}

	for _, r := range confidenceRanges {
		if maxGap*time.Duration(r.multiplier) <= requiredWindow {
			return r.level
		}
	}
	return ConfidenceLow
}

// SafetyStatus classifies the overall safety posture of an evaluation.
type SafetyStatus string

const (
	SafetyStatusSafe       SafetyStatus = "SAFE"
	SafetyStatusBorderline SafetyStatus = "BORDERLINE"
	SafetyStatusUnsafe     SafetyStatus = "UNSAFE"
)

// ClassifySafetyStatus derives a SafetyStatus from violation count and
// upcoming risk items. UNSAFE if any violations exist; BORDERLINE if
// assets are approaching or at their unsafe threshold; SAFE otherwise.
func ClassifySafetyStatus(violations int, upcomingRisks risk.Items) SafetyStatus {
	if violations > 0 {
		return SafetyStatusUnsafe
	}
	if upcomingRisks.HasAnyRisk() {
		return SafetyStatusBorderline
	}
	return SafetyStatusSafe
}

// Decision represents the outcome of evaluating an control against an asset.
type Decision string

const (
	// DecisionViolation indicates the control was violated.
	DecisionViolation Decision = "VIOLATION"
	// DecisionPass indicates the asset complies with the control.
	DecisionPass Decision = "PASS"
	// DecisionInconclusive indicates insufficient data to determine compliance.
	DecisionInconclusive Decision = "INCONCLUSIVE"
	// DecisionNotApplicable indicates the control does not apply to this asset.
	DecisionNotApplicable Decision = "NOT_APPLICABLE"
	// DecisionSkipped indicates the asset was skipped (e.g., due to ignore rules).
	DecisionSkipped Decision = "SKIPPED"
)

// Row represents the evaluation outcome for a single (control, asset) pair.
// Every evaluated pair gets exactly one row with an explicit decision.
type Row struct {
	ControlID   kernel.ControlID `json:"control_id"`
	AssetID     asset.ID         `json:"asset_id"`
	AssetType   kernel.AssetType `json:"asset_type"`
	AssetDomain string           `json:"asset_domain"`
	Decision    Decision         `json:"decision"`
	Confidence  ConfidenceLevel  `json:"confidence"`
	Evidence    *Evidence        `json:"evidence,omitempty"`
	WhyNow      string           `json:"why_now,omitempty"`
	Reason      string           `json:"reason,omitempty"` // For SKIPPED/NOT_APPLICABLE
}

// MarkInconclusive updates the row to an inconclusive decision with the given reason.
func (row *Row) MarkInconclusive(reason string) {
	if row == nil {
		return
	}
	row.Decision = DecisionInconclusive
	row.Confidence = ConfidenceInconclusive
	row.Reason = reason
}

// Summary provides aggregate statistics.
type Summary struct {
	AssetsEvaluated int `json:"assets_evaluated"`
	AttackSurface   int `json:"attack_surface"`
	Violations      int `json:"violations"`
}

// SkippedControl represents a control that was skipped during evaluation.
type SkippedControl struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// Result holds the complete evaluation output.
type Result struct {
	Run                RunInfo              `json:"run"`
	Summary            Summary              `json:"summary"`
	Findings           []Finding            `json:"findings"`
	SuppressedFindings []SuppressedFinding  `json:"suppressed_findings,omitempty"`
	Skipped            []SkippedControl     `json:"skipped,omitempty"`
	SkippedAssets      []asset.SkippedAsset `json:"skipped_assets,omitempty"`
	Metadata           Metadata             `json:"-"`
	// Rows contains per-pair evaluation decisions (populated when --explain-all is enabled)
	Rows []Row `json:"rows,omitempty"`
}

// FindFinding returns the finding matching the given control and asset IDs, or nil.
func (r Result) FindFinding(controlID kernel.ControlID, assetID asset.ID) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ControlID == controlID && r.Findings[i].AssetID == assetID {
			return &r.Findings[i]
		}
	}
	return nil
}

// DomainCount holds the count of violation rows for a single asset domain.
type DomainCount struct {
	Domain string
	Count  int
}

// GroupViolationsByDomain returns sorted domain counts from violation rows.
func GroupViolationsByDomain(rows []Row) []DomainCount {
	counts := make(map[string]int)
	for _, row := range rows {
		if row.Decision != DecisionViolation {
			continue
		}
		domain := strings.TrimSpace(row.AssetDomain)
		if domain == "" {
			domain = "unknown"
		}
		counts[domain]++
	}

	result := make([]DomainCount, 0, len(counts))
	for domain, count := range counts {
		result = append(result, DomainCount{Domain: domain, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})
	return result
}

// SafetyStatus classifies the overall safety posture of this evaluation result.
// UNSAFE if any violations exist, SAFE otherwise. Upcoming risk items (which
// can produce BORDERLINE) are not tracked in Result; callers with risk data
// should use ClassifySafetyStatus directly.
func (r Result) SafetyStatus() SafetyStatus {
	return ClassifySafetyStatus(len(r.Findings), nil)
}
