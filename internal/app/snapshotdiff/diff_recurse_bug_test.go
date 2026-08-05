package snapshotdiff

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/diff"
)

func TestDiff_NestedMapRemovedRecursesLeafRisk(t *testing.T) {
	before := asset.Snapshot{
		CapturedAt: time.Now(),
		Assets: []asset.Asset{
			{
				ID:   "ast-1",
				Type: "aws_s3_bucket",
				Properties: map[string]any{
					"storage": map[string]any{
						"access": map[string]any{
							"public_read": true,
						},
					},
				},
			},
		},
	}

	// After snapshot has no storage property
	after := asset.Snapshot{
		CapturedAt: time.Now(),
		Assets: []asset.Asset{
			{
				ID:         "ast-1",
				Type:       "aws_s3_bucket",
				Properties: map[string]any{},
			},
		},
	}

	res := Diff(before, after)
	if len(res.PropertyChanges) == 0 {
		t.Fatalf("expected property changes")
	}

	// Should recurse to leaf property "storage.access.public_read" and classify as RiskDecreasing (public_read was true, now absent/nil)
	foundLeaf := false
	for _, pc := range res.PropertyChanges {
		if pc.Property == "storage.access.public_read" {
			foundLeaf = true
			if pc.RiskDirection != diff.RiskDecreasing {
				t.Errorf("expected RiskDecreasing for removed public_read property, got %v", pc.RiskDirection)
			}
		}
	}

	if !foundLeaf {
		t.Errorf("expected recursive property path 'storage.access.public_read', got changes: %+v", res.PropertyChanges)
	}
}
