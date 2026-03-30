package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestAudit002(t *testing.T) {
	inv := ControlRegistry.Lookup("AUDIT.002")
	if inv == nil {
		t.Fatal("AUDIT.002 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name: "object_level_logging enabled — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"logging": map[string]any{
						"object_level_logging": map[string]any{
							"enabled": true,
						},
					},
				},
			})),
			wantPass: true,
		},
		{
			name: "object_level_logging disabled — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"logging": map[string]any{
						"object_level_logging": map[string]any{
							"enabled": false,
						},
					},
				},
			})),
			wantPass: false,
		},
		{
			name: "object_level_logging map missing — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"logging": map[string]any{},
				},
			})),
			wantPass: false,
		},
		{
			name: "logging map missing — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{},
			})),
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
			if !tc.wantPass && r.Finding == "" {
				t.Error("Finding should not be empty on failure")
			}
			if !tc.wantPass && r.Remediation == "" {
				t.Error("Remediation should not be empty on failure")
			}
		})
	}
}
