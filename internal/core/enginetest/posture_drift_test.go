package enginetest

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
)

func TestComputePostureDrift(t *testing.T) {
	t0 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 10, 6, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)

	newLifecycleBuilder := func() *asset.ExposureLifecycle {
		tl := asset.NewExposureLifecycle(asset.Asset{ID: "res:test"})
		return tl
	}

	tests := []struct {
		name            string
		setup           func(*asset.ExposureLifecycle)
		wantNil         bool
		wantPattern     evaluation.DriftPattern
		wantWindowCount int
	}{
		{
			name: "not currently unsafe returns nil",
			setup: func(tl *asset.ExposureLifecycle) {
				_ = tl.RecordCheck(t0, false)
			},
			wantNil: true,
		},
		{
			name: "persistent: unsafe since first observation",
			setup: func(tl *asset.ExposureLifecycle) {
				_ = tl.RecordCheck(t0, true)
			},
			wantPattern:     "persistent",
			wantWindowCount: 1,
		},
		{
			name: "degraded: was safe before first unsafe",
			setup: func(tl *asset.ExposureLifecycle) {
				_ = tl.RecordCheck(t0, false)
				_ = tl.RecordCheck(t1, true)
			},
			wantPattern:     "degraded",
			wantWindowCount: 1,
		},
		{
			name: "intermittent: one closed exposure window plus open",
			setup: func(tl *asset.ExposureLifecycle) {
				_ = tl.RecordCheck(t0, true)
				_ = tl.RecordCheck(t1, false)
				_ = tl.RecordCheck(t2, true)
			},
			wantPattern:     "intermittent",
			wantWindowCount: 2,
		},
		{
			name: "intermittent: two closed exposure windows plus open",
			setup: func(tl *asset.ExposureLifecycle) {
				_ = tl.RecordCheck(t0, true)
				_ = tl.RecordCheck(t1, false)
				_ = tl.RecordCheck(t1, true)
				_ = tl.RecordCheck(t2, false)
				_ = tl.RecordCheck(t2, true)
			},
			wantPattern:     "intermittent",
			wantWindowCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lifecycle := newLifecycleBuilder()
			tt.setup(lifecycle)
			got := evaluation.ComputePostureDrift(lifecycle)
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
			if got.ExposureWindowCount != tt.wantWindowCount {
				t.Errorf("exposure_window_count: got %d, want %d", got.ExposureWindowCount, tt.wantWindowCount)
			}
		})
	}
}
