package domain

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
)

func TestComputePostureDrift(t *testing.T) {
	t0 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 10, 6, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

	newTimeline := func() *asset.Timeline {
		return asset.NewTimeline(asset.Asset{ID: "res:test"})
	}

	tests := []struct {
		name           string
		setup          func(*asset.Timeline)
		wantNil        bool
		wantPattern    evaluation.DriftPattern
		wantEpisodeCnt int
	}{
		{
			name: "not currently unsafe returns nil",
			setup: func(tl *asset.Timeline) {
				tl.RecordObservation(t0, false)
			},
			wantNil: true,
		},
		{
			name: "persistent: unsafe since first observation",
			setup: func(tl *asset.Timeline) {
				tl.RecordObservation(t0, true)
			},
			wantPattern:    "persistent",
			wantEpisodeCnt: 1,
		},
		{
			name: "degraded: was safe before first unsafe",
			setup: func(tl *asset.Timeline) {
				tl.RecordObservation(t0, false)
				tl.RecordObservation(t1, true)
			},
			wantPattern:    "degraded",
			wantEpisodeCnt: 1,
		},
		{
			name: "intermittent: one closed episode plus open",
			setup: func(tl *asset.Timeline) {
				tl.RecordObservation(t0, true)
				tl.RecordObservation(t1, false)
				tl.RecordObservation(t2, true)
			},
			wantPattern:    "intermittent",
			wantEpisodeCnt: 2,
		},
		{
			name: "intermittent: two closed episodes plus open",
			setup: func(tl *asset.Timeline) {
				tl.RecordObservation(t0, true)
				tl.RecordObservation(t1, false)
				tl.RecordObservation(t1, true)
				tl.RecordObservation(t2, false)
				tl.RecordObservation(t2, true)
			},
			wantPattern:    "intermittent",
			wantEpisodeCnt: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeline := newTimeline()
			tt.setup(timeline)
			got := evaluation.ComputePostureDrift(timeline)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil PostureDrift, got nil")
			}
			if got.Pattern != tt.wantPattern {
				t.Errorf("pattern: got %q, want %q", got.Pattern, tt.wantPattern)
			}
			if got.EpisodeCount != tt.wantEpisodeCnt {
				t.Errorf("episode_count: got %d, want %d", got.EpisodeCount, tt.wantEpisodeCnt)
			}
		})
	}
}
