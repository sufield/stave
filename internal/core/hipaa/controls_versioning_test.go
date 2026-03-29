package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func versionedBucket(id string, enabled bool) asset.Asset {
	return s3Bucket(id, map[string]any{
		"storage": map[string]any{
			"versioning": map[string]any{"enabled": enabled},
		},
	})
}

func TestControls002(t *testing.T) {
	inv := ControlRegistry.Lookup("CONTROLS.002")
	if inv == nil {
		t.Fatal("CONTROLS.002 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name:     "versioning enabled — pass",
			snap:     snap(versionedBucket("b", true)),
			wantPass: true,
		},
		{
			name:     "versioning disabled — fail",
			snap:     snap(versionedBucket("b", false)),
			wantPass: false,
		},
		{
			name:     "no versioning properties — fail",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: false,
		},
		{
			name:     "empty snapshot — pass",
			snap:     snap(),
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := inv.Evaluate(tc.snap)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass: got %v, want %v (finding: %s)", r.Pass, tc.wantPass, r.Finding)
			}
			if !tc.wantPass && r.Severity != Medium {
				t.Errorf("Severity: got %s, want MEDIUM", r.Severity)
			}
		})
	}
}
