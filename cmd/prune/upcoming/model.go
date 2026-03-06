package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
)

type upcomingItem struct {
	DueAt          time.Time
	Status         string
	ControlID      string
	AssetID        string
	AssetType      string
	FirstUnsafeAt  time.Time
	LastSeenUnsafe time.Time
	Threshold      time.Duration
	Remaining      time.Duration
}

type upcomingSummary struct {
	Overdue int
	DueNow  int
	DueSoon int
	Later   int
	Total   int
}

type upcomingOutput struct {
	GeneratedAt  time.Time       `json:"generated_at"`
	ControlsDir  string          `json:"controls_dir"`
	Observations string          `json:"observations_dir"`
	MaxUnsafe    string          `json:"max_unsafe"`
	DueSoon      string          `json:"due_soon"`
	Summary      upcomingSummary `json:"summary"`
	Items        []upcomingItem  `json:"items"`
}

type upcomingFilter struct {
	controlIDs    map[kernel.ControlID]struct{}
	resourceTypes map[kernel.AssetType]struct{}
	statuses      map[string]struct{}
	dueWithin     *time.Duration
}

// UpcomingFilterCriteria holds filter rules for upcoming action items.
type UpcomingFilterCriteria struct {
	ControlIDs []kernel.ControlID
	AssetTypes []kernel.AssetType
	Statuses   []string
	DueWithin  *time.Duration
}

// UpcomingComputeOptions holds configuration for computing upcoming items.
type UpcomingComputeOptions struct {
	GlobalMaxUnsafe time.Duration
	Now             time.Time
}

// UpcomingRenderOptions holds configuration for rendering upcoming markdown.
type UpcomingRenderOptions struct {
	Now              time.Time
	DueSoonThreshold time.Duration
}

type upcomingRunOptions struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       time.Duration
	MaxUnsafeRaw    string
	DueSoon         time.Duration
	DueSoonRaw      string
	Now             time.Time
	Format          ui.OutputFormat
	Filter          upcomingFilter
}
