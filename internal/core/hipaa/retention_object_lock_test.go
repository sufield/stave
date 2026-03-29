package hipaa

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func lockBucket(id string, enabled bool, mode string) asset.Asset {
	lock := map[string]any{"enabled": enabled}
	if mode != "" {
		lock["mode"] = mode
	}
	return s3Bucket(id, map[string]any{
		"storage": map[string]any{"object_lock": lock},
	})
}

func TestRetention002(t *testing.T) {
	inv := ControlRegistry.Lookup("RETENTION.002")
	if inv == nil {
		t.Fatal("RETENTION.002 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
		wantSev  Severity
	}{
		{
			name:     "Compliance mode — pass",
			snap:     snap(lockBucket("b", true, "COMPLIANCE")),
			wantPass: true,
		},
		{
			name:     "Governance mode — fail HIGH",
			snap:     snap(lockBucket("b", true, "GOVERNANCE")),
			wantPass: false,
			wantSev:  High,
		},
		{
			name:     "lock enabled, no mode set — fail HIGH",
			snap:     snap(lockBucket("b", true, "")),
			wantPass: false,
			wantSev:  High,
		},
		{
			name:     "lock disabled — fail CRITICAL",
			snap:     snap(lockBucket("b", false, "")),
			wantPass: false,
			wantSev:  Critical,
		},
		{
			name:     "no lock properties — fail CRITICAL",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: false,
			wantSev:  Critical,
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
			if !tc.wantPass && r.Severity != tc.wantSev {
				t.Errorf("Severity: got %s, want %s", r.Severity, tc.wantSev)
			}
		})
	}
}
