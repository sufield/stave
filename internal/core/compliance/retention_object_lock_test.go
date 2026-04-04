package compliance

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
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
	ctl := ControlRegistry.Lookup("RETENTION.002")
	if ctl == nil {
		t.Fatal("RETENTION.002 not registered")
	}

	tests := []struct {
		name     string
		snap     asset.Snapshot
		wantPass bool
		wantSev  policy.Severity
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
			wantSev:  policy.SeverityHigh,
		},
		{
			name:     "lock enabled, no mode set — fail HIGH",
			snap:     snap(lockBucket("b", true, "")),
			wantPass: false,
			wantSev:  policy.SeverityHigh,
		},
		{
			name:     "lock disabled — fail CRITICAL",
			snap:     snap(lockBucket("b", false, "")),
			wantPass: false,
			wantSev:  policy.SeverityCritical,
		},
		{
			name:     "no lock properties — fail CRITICAL",
			snap:     snap(s3Bucket("b", map[string]any{})),
			wantPass: false,
			wantSev:  policy.SeverityCritical,
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
			if !tc.wantPass && r.Severity != tc.wantSev {
				t.Errorf("Severity: got %s, want %s", r.Severity, tc.wantSev)
			}
		})
	}
}
