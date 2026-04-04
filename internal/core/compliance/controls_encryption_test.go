package compliance

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func encBucket(id string, atRest bool, algorithm, keyID string) asset.Asset {
	enc := map[string]any{"at_rest_enabled": atRest}
	if algorithm != "" {
		enc["algorithm"] = algorithm
	}
	if keyID != "" {
		enc["kms_master_key_id"] = keyID
	}
	return s3Bucket(id, map[string]any{
		"storage": map[string]any{"encryption": enc},
	})
}

func TestControls001(t *testing.T) {
	ctl := ControlRegistry.Lookup("CONTROLS.001")
	if ctl == nil {
		t.Fatal("CONTROLS.001 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name:     "encryption enabled — pass",
			snap:     snap(encBucket("b", true, "AES256", "")),
			wantPass: true,
		},
		{
			name:     "encryption disabled — fail",
			snap:     snap(encBucket("b", false, "", "")),
			wantPass: false,
		},
		{
			name:     "no encryption properties — fail",
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
			r := ctl.Evaluate(tc.snap)
			if r.Pass != tc.wantPass {
				t.Errorf("Pass: got %v, want %v (finding: %s)", r.Pass, tc.wantPass, r.Finding)
			}
		})
	}
}
