package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestAccess006(t *testing.T) {
	inv := ControlRegistry.Lookup("ACCESS.006")
	if inv == nil {
		t.Fatal("ACCESS.006 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name: "attached true and not default full access — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"network": map[string]any{
						"vpc_endpoint_policy": map[string]any{
							"attached":               true,
							"is_default_full_access": false,
						},
					},
				},
			})),
			wantPass: true,
		},
		{
			name: "attached true but is_default_full_access true — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"network": map[string]any{
						"vpc_endpoint_policy": map[string]any{
							"attached":               true,
							"is_default_full_access": true,
						},
					},
				},
			})),
			wantPass: false,
		},
		{
			name: "attached false — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"network": map[string]any{
						"vpc_endpoint_policy": map[string]any{
							"attached": false,
						},
					},
				},
			})),
			wantPass: false,
		},
		{
			name: "network map missing — fail",
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
