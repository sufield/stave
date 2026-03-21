package domain

import (
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

func TestScopeFilter_AllowlistMatchesIDAndExternalID(t *testing.T) {
	f := asset.NewScopeFilter([]string{"bucket-allowed", "arn:aws:s3:::arn-allowed"}, nil)

	if !f.IsInScope(asset.Asset{ID: "bucket-allowed"}) {
		t.Fatal("expected resource ID allowlist match")
	}

	if !f.IsInScope(asset.Asset{
		ID: "other",
		Properties: map[string]any{
			"external_id": "arn:aws:s3:::arn-allowed",
		},
	}) {
		t.Fatal("expected external ID allowlist match")
	}

	if f.IsInScope(asset.Asset{ID: "not-allowed"}) {
		t.Fatal("expected resource outside allowlist to be out of scope")
	}
}

func TestScopeFilter_TagMatchingIsNormalized(t *testing.T) {
	f := asset.NewScopeFilter(nil, map[string][]string{
		" DataDomain ": {" HEALTH "},
		"owner":        {}, // any non-empty value
	})

	if !f.IsInScope(asset.Asset{
		ID: "r1",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]any{
					"datadomain": "health",
				},
			},
		},
	}) {
		t.Fatal("expected normalized key/value tag match")
	}

	if !f.IsInScope(asset.Asset{
		ID: "r2",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]string{
					"OWNER": "team-a",
				},
			},
		},
	}) {
		t.Fatal("expected any-value tag key match")
	}

	if f.IsInScope(asset.Asset{
		ID: "r3",
		Properties: map[string]any{
			"storage": map[string]any{
				"tags": map[string]any{
					"owner": "   ",
				},
			},
		},
	}) {
		t.Fatal("expected empty any-value tag to be out of scope")
	}
}

func TestScopeFilter_FilterSnapshots(t *testing.T) {
	f := asset.NewScopeFilter(nil, map[string][]string{
		"containsPHI": {"true"},
	})

	snapshots := []asset.Snapshot{
		{
			CapturedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Assets: []asset.Asset{
				{ID: "out", Properties: map[string]any{"storage": map[string]any{"tags": map[string]any{"containsPHI": "false"}}}},
			},
		},
		{
			CapturedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			Assets: []asset.Asset{
				{ID: "in", Properties: map[string]any{"storage": map[string]any{"tags": map[string]any{"containsPHI": "true"}}}},
				{ID: "out", Properties: map[string]any{"storage": map[string]any{"tags": map[string]any{"containsPHI": "false"}}}},
			},
		},
	}

	got := asset.FilterSnapshots(f, snapshots)
	if len(got) != 1 {
		t.Fatalf("filtered snapshot count = %d, want 1", len(got))
	}
	if len(got[0].Assets) != 1 {
		t.Fatalf("filtered resource count = %d, want 1", len(got[0].Assets))
	}
	if got[0].Assets[0].ID != "in" {
		t.Fatalf("filtered resource ID = %q, want in", got[0].Assets[0].ID)
	}
}

func TestScopeFilter_ConstraintFreeAfterNormalizationIsUniversal(t *testing.T) {
	f := asset.NewScopeFilter(
		[]string{"   "},
		map[string][]string{
			"   ": {"   "},
		},
	)

	if !f.IsInScope(asset.Asset{ID: "any-resource"}) {
		t.Fatal("expected universal scope filter when normalized constraints are empty")
	}
}

func TestNewScopeFilter_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		allowlist     []string
		tagSpecs      map[string][]string
		wantUniversal bool
	}{
		{
			name:          "Strictly nil inputs",
			allowlist:     nil,
			tagSpecs:      nil,
			wantUniversal: true,
		},
		{
			name:          "Empty slices and maps",
			allowlist:     []string{},
			tagSpecs:      map[string][]string{},
			wantUniversal: true,
		},
		{
			name:          "Allowlist with only whitespace or empty strings",
			allowlist:     []string{" ", ""},
			tagSpecs:      nil,
			wantUniversal: true,
		},
		{
			name:      "TagSpecs with invalid keys or empty value sets",
			allowlist: nil,
			tagSpecs: map[string][]string{
				" ": {},
				"":  {},
			},
			wantUniversal: true,
		},
		{
			name:      "Functional tags should NOT return universal",
			allowlist: nil,
			tagSpecs: map[string][]string{
				"Environment": {"Production"},
			},
			wantUniversal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := asset.NewScopeFilter(tt.allowlist, tt.tagSpecs)
			if got == nil {
				t.Fatal("NewScopeFilter() returned nil")
			}

			// Behavior-based universal check: universal filters admit any asset.
			unknown := asset.Asset{ID: "resource-not-in-allowlist-or-tags"}
			isUniversalBehavior := got.IsInScope(unknown)
			if isUniversalBehavior != tt.wantUniversal {
				t.Errorf("NewScopeFilter() universal behavior = %v, want %v", isUniversalBehavior, tt.wantUniversal)
			}

			if !tt.wantUniversal {
				// Ensure constrained filter still admits a valid in-scope asset.
				inScope := asset.Asset{
					ID: "resource-with-matching-tags",
					Properties: map[string]any{
						"storage": map[string]any{
							"tags": map[string]any{
								"environment": "production",
							},
						},
					},
				}
				if !got.IsInScope(inScope) {
					t.Error("NewScopeFilter() constrained filter did not admit matching resource")
				}
			}
		})
	}
}
