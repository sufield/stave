package findings

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// ExposureRank captures a finding's priority score with full factor
// breakdown for traceability. The breakdown lets operators understand
// WHY a finding ranks where it does — not just that it does.
//
// Moved from internal/core/evaluation/risk/exposure_rank.go during the
// chain-engine untangle (may8.md sequence) so report/ stops importing
// risk/. risk.ExposureRank + risk.ScoreBreakdown remain as brief
// local aliases for producer-side code in risk/ (RankExposures and
// the formula helpers); external consumers reach for findings.X
// directly.
type ExposureRank struct {
	FindingIndex  int                  `json:"finding_index"`
	ControlID     kernel.ControlID     `json:"control_id"`
	AssetID       asset.ID             `json:"asset_id"`
	ExposureScore kernel.ExposureScore `json:"exposure_score"`
	Breakdown     ScoreBreakdown       `json:"breakdown"`
	SilentKiller  bool                 `json:"silent_killer"`
}

// IsDanglingReference reports whether this rank entry points at a
// finding index outside the supplied findings count — a referential
// integrity failure caused by a stale ranker, an upstream filter
// that removed findings without updating indices, or a hand-built
// fixture with mismatched parallel arrays. Encapsulates the
// (idx<0 || idx>=len) bounds probe so the caller describes the
// *relationship* (dangling pointer) instead of the slice arithmetic.
// A future move from index-based to ID-based correlation lands here
// without touching the call site.
func (r *ExposureRank) IsDanglingReference(findingsCount int) bool {
	if r == nil {
		return true
	}
	return r.FindingIndex < 0 || r.FindingIndex >= findingsCount
}

// ScoreBreakdown provides the traceable factor decomposition.
type ScoreBreakdown struct {
	BaseScore          int                `json:"base_score"`
	DurationFactor     float64            `json:"duration_factor"`
	BlastMultiplier    kernel.BlastRadius `json:"blast_multiplier"`
	ExposureMultiplier float64            `json:"exposure_multiplier"`
	ChainBonus         float64            `json:"chain_bonus"`
	// BlindMultiplier scales the score continuously with how long the
	// finding has been unsafe. DurationFactor steps in coarse buckets
	// (1.0/1.5/2.0/3.0/5.0) for traceability; BlindMultiplier breaks
	// ties within a bucket so a 360-day exposure outranks a 100-day
	// exposure even though both fall in the same DurationFactor bucket.
	BlindMultiplier float64 `json:"blind_multiplier"`
	DaysBlind       float64 `json:"days_blind"`
}
