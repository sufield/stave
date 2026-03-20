package hygiene

import (
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// HygieneFilters captures the active filter criteria for a hygiene report.
type HygieneFilters struct {
	ControlIDs []kernel.ControlID `json:"control_ids"`
	AssetTypes []kernel.AssetType `json:"asset_types"`
	Statuses   []risk.Status      `json:"statuses"`
	DueWithin  string             `json:"due_within"`
}

// Output is the structured representation of a hygiene report.
type Output struct {
	GeneratedAt      time.Time                  `json:"generated_at"`
	LookbackStart    time.Time                  `json:"lookback_start"`
	LookbackDuration string                     `json:"lookback_duration"`
	DueSoonThreshold string                     `json:"due_soon_threshold"`
	Filters          HygieneFilters             `json:"filters"`
	SnapshotStats    appcontracts.SnapshotStats `json:"snapshot_stats"`
	RiskStats        appcontracts.RiskStats     `json:"risk_stats"`
	Trend            []evaluation.TrendMetric   `json:"trend"`
}
