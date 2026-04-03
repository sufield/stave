package compliance

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func loggingBucket(id, targetBucket string) asset.Asset {
	logging := map[string]any{}
	if targetBucket != "" {
		logging["target_bucket"] = targetBucket
	}
	return s3Bucket(id, map[string]any{
		"storage": map[string]any{"logging": logging},
	})
}

func TestAudit001(t *testing.T) {
	inv := ControlRegistry.Lookup("AUDIT.001")
	if inv == nil {
		t.Fatal("AUDIT.001 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
	}{
		{
			name:     "logging enabled with target — pass",
			snap:     snap(loggingBucket("b", "log-bucket")),
			wantPass: true,
		},
		{
			name:     "logging enabled but empty target — fail",
			snap:     snap(loggingBucket("b", "")),
			wantPass: false,
		},
		{
			name:     "no logging properties — fail",
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
			if !tc.wantPass && !strings.Contains(r.Finding, "retroactively") {
				t.Error("Finding should state logs cannot be obtained retroactively")
			}
			if !tc.wantPass && r.Severity != policy.SeverityCritical {
				t.Errorf("Severity: got %s, want CRITICAL", r.Severity)
			}
		})
	}
}
