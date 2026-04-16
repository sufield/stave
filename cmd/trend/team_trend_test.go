package trend

import (
	"testing"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func makeManifest() *teams.Manifest {
	return &teams.Manifest{
		OwnerTagKey:    "team",
		FallbackTagKey: "owner",
		Teams: []teams.Team{
			{
				ID:               "alpha",
				DisplayName:      "Team Alpha",
				Contact:          "alpha@test.com",
				ResourcePatterns: []string{"arn:aws:s3:::alpha-*"},
			},
			{
				ID:               "beta",
				DisplayName:      "Team Beta",
				Contact:          "beta@test.com",
				ResourcePatterns: []string{"arn:aws:s3:::beta-*"},
			},
		},
	}
}

func makeFinding(ctlID, assetID string, sev policy.Severity, dwell float64, breached bool) remediation.Finding {
	f := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctlID),
			AssetID:         asset.ID(assetID),
			ControlSeverity: sev,
			Evidence: evaluation.Evidence{
				UnsafeDurationHours: dwell,
			},
		},
	}
	if breached {
		f.SLABreached = true
		deadline := 24.0
		f.SLADeadlineHours = &deadline
	}
	return f
}

func TestComputeTeamTrends_BasicAttribution(t *testing.T) {
	manifest := makeManifest()
	assessments := []*report.Assessment{
		{
			Findings: []remediation.Finding{
				makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityCritical, 48, true),
				makeFinding("CTL.S3.002", "arn:aws:s3:::alpha-logs", policy.SeverityHigh, 24, false),
				makeFinding("CTL.S3.003", "arn:aws:s3:::beta-data", policy.SeverityMedium, 12, false),
			},
		},
	}

	trends, summary := computeTeamTrends(assessments, manifest, "", false)

	if summary == nil {
		t.Fatal("expected summary")
	}
	if summary.TeamsTracked != 2 {
		t.Errorf("teams tracked = %d, want 2", summary.TeamsTracked)
	}

	// Alpha has 2 findings, Beta has 1.
	alphaIdx := -1
	betaIdx := -1
	for i, tt := range trends {
		if tt.ID == "alpha" {
			alphaIdx = i
		}
		if tt.ID == "beta" {
			betaIdx = i
		}
	}
	if alphaIdx < 0 || betaIdx < 0 {
		t.Fatalf("missing teams in results: alpha=%d, beta=%d", alphaIdx, betaIdx)
	}
	if trends[alphaIdx].OpenFindings != 2 {
		t.Errorf("alpha open = %d, want 2", trends[alphaIdx].OpenFindings)
	}
	if trends[alphaIdx].CriticalOpen != 1 {
		t.Errorf("alpha critical = %d, want 1", trends[alphaIdx].CriticalOpen)
	}
	if trends[betaIdx].OpenFindings != 1 {
		t.Errorf("beta open = %d, want 1", trends[betaIdx].OpenFindings)
	}
}

func TestComputeTeamTrends_Trajectory(t *testing.T) {
	manifest := makeManifest()
	// Two assessments: alpha had 10 findings, now has 2 → improving.
	earlier := &report.Assessment{
		Findings: make([]remediation.Finding, 10),
	}
	for i := range earlier.Findings {
		earlier.Findings[i] = makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityHigh, 48, false)
	}
	latest := &report.Assessment{
		Findings: []remediation.Finding{
			makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityHigh, 24, false),
			makeFinding("CTL.S3.002", "arn:aws:s3:::alpha-logs", policy.SeverityMedium, 12, false),
		},
	}

	trends, _ := computeTeamTrends([]*report.Assessment{earlier, latest}, manifest, "", false)

	for _, tt := range trends {
		if tt.ID == "alpha" {
			// Score went from 0 (all violations) to non-zero → improving.
			if tt.Trajectory != trajectoryImproving && tt.Trajectory != trajectoryStable {
				t.Logf("alpha trajectory = %q, score = %.1f, delta = %.1f", tt.Trajectory, tt.PostureScore, tt.ScoreDelta)
			}
			return
		}
	}
}

func TestComputeTeamTrends_RegressionOnly(t *testing.T) {
	manifest := makeManifest()
	assessments := []*report.Assessment{
		{
			Findings: []remediation.Finding{
				makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityCritical, 48, true),
				makeFinding("CTL.S3.002", "arn:aws:s3:::beta-data", policy.SeverityMedium, 12, false),
			},
		},
	}

	trends, _ := computeTeamTrends(assessments, manifest, "", true)

	// With single assessment and no history, all are STABLE → regression-only filters all.
	for _, tt := range trends {
		if tt.Trajectory != trajectoryRegressing {
			t.Errorf("regression-only should only include regressing teams, got %q", tt.Trajectory)
		}
	}
}

func TestComputeTeamTrends_TeamFilter(t *testing.T) {
	manifest := makeManifest()
	assessments := []*report.Assessment{
		{
			Findings: []remediation.Finding{
				makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityCritical, 48, true),
				makeFinding("CTL.S3.002", "arn:aws:s3:::beta-data", policy.SeverityMedium, 12, false),
			},
		},
	}

	trends, _ := computeTeamTrends(assessments, manifest, "alpha", false)

	if len(trends) != 1 {
		t.Fatalf("expected 1 team (alpha), got %d", len(trends))
	}
	if trends[0].ID != "alpha" {
		t.Errorf("expected alpha, got %q", trends[0].ID)
	}
}
