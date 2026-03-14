package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
)

// UpcomingItem represents a single upcoming snapshot action item.
type UpcomingItem struct {
	DueAt          time.Time
	Status         risk.Status
	ControlID      kernel.ControlID
	AssetID        asset.ID
	AssetType      kernel.AssetType
	FirstUnsafeAt  time.Time
	LastSeenUnsafe time.Time
	Threshold      time.Duration
	Remaining      time.Duration
}

// UpcomingSummary holds aggregate counts for upcoming items by status.
type UpcomingSummary struct {
	Overdue int
	DueNow  int
	DueSoon int
	Later   int
	Total   int
}

// UpcomingOutput is the JSON-serializable output for the upcoming command.
type UpcomingOutput struct {
	GeneratedAt  time.Time       `json:"generated_at"`
	ControlsDir  string          `json:"controls_dir"`
	Observations string          `json:"observations_dir"`
	MaxUnsafe    string          `json:"max_unsafe"`
	DueSoon      string          `json:"due_soon"`
	Summary      UpcomingSummary `json:"summary"`
	Items        []UpcomingItem  `json:"items"`
}

// UpcomingFilterCriteria holds filter rules for upcoming action items.
// A DueWithin of 0 means no duration filter is applied.
type UpcomingFilterCriteria struct {
	ControlIDs []kernel.ControlID
	AssetTypes []kernel.AssetType
	Statuses   []string
	DueWithin  time.Duration
}

// UpcomingRenderOptions holds configuration for rendering upcoming markdown.
type UpcomingRenderOptions struct {
	Now              time.Time
	DueSoonThreshold time.Duration
}
