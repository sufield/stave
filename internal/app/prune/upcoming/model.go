package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// Snapshot represents a single upcoming snapshot action item.
type Snapshot struct {
	DueAt          time.Time
	Status         risk.ThresholdStatus
	ControlID      kernel.ControlID
	AssetID        asset.ID
	AssetType      kernel.AssetType
	FirstUnsafeAt  time.Time
	LastSeenUnsafe time.Time
	Threshold      time.Duration
	Remaining      time.Duration
}

// Summary holds aggregate counts for upcoming items by status.
type Summary struct {
	Overdue int
	DueNow  int
	DueSoon int
	Later   int
	Total   int
}

// Report is the JSON-serializable output for the upcoming command.
type Report struct {
	GeneratedAt       time.Time  `json:"generated_at"`
	ControlsDir       string     `json:"controls_dir"`
	Observations      string     `json:"observations_dir"`
	MaxUnsafeDuration string     `json:"max_unsafe"`
	DueSoon           string     `json:"due_soon"`
	Summary           Summary    `json:"summary"`
	Items             []Snapshot `json:"items"`
}

// FilterCriteria holds filter rules for upcoming action items.
// A DueWithin of 0 means no duration filter is applied.
type FilterCriteria struct {
	ControlIDs []kernel.ControlID
	AssetTypes []kernel.AssetType
	Statuses   []string
	DueWithin  time.Duration
}
