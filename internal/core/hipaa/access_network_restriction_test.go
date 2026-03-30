package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestAccess003(t *testing.T) {
	inv := ControlRegistry.Lookup("ACCESS.003")
	if inv == nil {
		t.Fatal("ACCESS.003 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name: "has_vpc_condition true — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"has_vpc_condition": true,
						"has_ip_condition":  false,
					},
				},
			})),
			wantPass: true,
		},
		{
			name: "has_ip_condition true — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"has_vpc_condition": false,
						"has_ip_condition":  true,
					},
				},
			})),
			wantPass: true,
		},
		{
			name: "both true — pass",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"has_vpc_condition": true,
						"has_ip_condition":  true,
					},
				},
			})),
			wantPass: true,
		},
		{
			name: "both false — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{
					"access": map[string]any{
						"has_vpc_condition": false,
						"has_ip_condition":  false,
					},
				},
			})),
			wantPass: false,
		},
		{
			name: "access map missing — fail",
			snap: snap(s3Bucket("test-bucket", map[string]any{
				"storage": map[string]any{},
			})),
			wantPass: false,
		},
		{
			name:     "storage map missing — fail",
			snap:     snap(s3Bucket("test-bucket", map[string]any{})),
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
