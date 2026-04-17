package teamgate

import (
	"testing"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func finding(ctl string, ast string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID(ast),
			ControlSeverity: sev,
		},
	}
}

func testManifest() *teams.Manifest {
	return &teams.Manifest{
		OwnerTagKey: "team",
		Teams: []teams.Team{
			{ID: "payments", DisplayName: "Payments", ResourcePatterns: []string{"arn:aws:s3:::payments-*"}},
			{ID: "platform", DisplayName: "Platform", IsDefault: true},
		},
	}
}

func TestEvaluate_TeamADoesNotAffectTeamB(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", "arn:aws:s3:::payments-bucket", policy.SeverityCritical),
		finding("CTL.B.001", "arn:aws:ec2::123:instance/web", policy.SeverityHigh),
	}

	// Platform team should only see the EC2 finding (default team).
	result := Evaluate(Input{
		Findings: findings,
		Manifest: testManifest(),
		TeamID:   "platform",
		Thresholds: Thresholds{
			MaxCritical: 0,
			MaxHigh:     5,
			MaxMedium:   -1,
		},
	})

	if result.CriticalCount != 0 {
		t.Errorf("platform critical = %d, want 0 (payments owns the critical)", result.CriticalCount)
	}
	if !result.Passed {
		t.Error("platform gate should pass — no critical findings owned by platform")
	}
}

func TestEvaluate_GateFailsOnThreshold(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", "arn:aws:s3:::payments-data", policy.SeverityCritical),
		finding("CTL.B.001", "arn:aws:s3:::payments-logs", policy.SeverityCritical),
	}

	result := Evaluate(Input{
		Findings: findings,
		Manifest: testManifest(),
		TeamID:   "payments",
		Thresholds: Thresholds{
			MaxCritical: 0,
			MaxHigh:     5,
			MaxMedium:   -1,
		},
	})

	if result.Passed {
		t.Error("payments gate should fail — 2 critical findings exceed threshold of 0")
	}
	if result.CriticalCount != 2 {
		t.Errorf("payments critical = %d, want 2", result.CriticalCount)
	}
}

func TestEvaluate_GatePassesWithinThreshold(t *testing.T) {
	findings := []remediation.Finding{
		finding("CTL.A.001", "arn:aws:s3:::payments-data", policy.SeverityHigh),
	}

	result := Evaluate(Input{
		Findings: findings,
		Manifest: testManifest(),
		TeamID:   "payments",
		Thresholds: Thresholds{
			MaxCritical: 0,
			MaxHigh:     5,
			MaxMedium:   -1,
		},
	})

	if !result.Passed {
		t.Error("gate should pass — 1 high finding within threshold of 5")
	}
}
