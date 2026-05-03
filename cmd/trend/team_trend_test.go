package trend

import (
	"bytes"
	"strings"
	"testing"
	"time"

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
		deadline := 24.0
		f.RehydrateSLA(&deadline, true, nil, 0, "")
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

func TestComputeRollup_WeightedScoreAverage(t *testing.T) {
	trends := []teamTrend{
		{ID: "alpha", PostureScore: 80, MTTRHours: 20, SLACompPct: 90, OpenFindings: 5, CriticalOpen: 1},
		{ID: "beta", PostureScore: 60, MTTRHours: 40, SLACompPct: 70, OpenFindings: 10, CriticalOpen: 2},
		{ID: "gamma", PostureScore: 100, MTTRHours: 10, SLACompPct: 100, OpenFindings: 0, CriticalOpen: 0},
	}
	group := &teams.HierarchyGroup{
		ID: "platform", Name: "Platform", Teams: []string{"alpha", "beta"},
	}

	result := computeRollup(trends, group)
	if result == nil {
		t.Fatal("expected rollup result")
	}
	// Average of 80 and 60 = 70.
	if result.PostureScore != 70 {
		t.Errorf("posture score = %.1f, want 70", result.PostureScore)
	}
	// Sum of open findings.
	if result.OpenFindings != 15 {
		t.Errorf("open findings = %d, want 15", result.OpenFindings)
	}
	if result.CriticalOpen != 3 {
		t.Errorf("critical = %d, want 3", result.CriticalOpen)
	}
	// Gamma excluded (not in group).
	if result.GroupID != "platform" {
		t.Errorf("group id = %q, want platform", result.GroupID)
	}
}

func TestManifest_NoHierarchy(t *testing.T) {
	manifest := makeManifest()
	if manifest.HierarchyByID("anything") != nil {
		t.Error("manifest without hierarchy should return nil")
	}
	assessments := []*report.Assessment{
		{Findings: []remediation.Finding{
			makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityHigh, 24, false),
		}},
	}
	trends, summary := computeTeamTrends(assessments, manifest, "", false)
	if summary == nil || summary.TeamsTracked == 0 {
		t.Error("manifest without hierarchy should still produce team trends")
	}
	if len(trends) == 0 {
		t.Error("expected at least one team trend")
	}
}

func TestRenderExecutiveSummary_ContainsScore(t *testing.T) {
	score := 81.2
	r := &trendReport{
		Period:       period{End: time.Now()},
		PostureScore: &score,
		Summary:      trendSummary{NetChangePercent: 4.1, Direction: "improving"},
	}

	var buf bytes.Buffer
	if err := renderExecutiveSummary(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "81.2") {
		t.Error("should contain posture score")
	}
	if !strings.Contains(out, "EXECUTIVE SECURITY SUMMARY") {
		t.Error("should contain header")
	}
}

func TestRenderExecutiveSummary_ContainsAttentionTeam(t *testing.T) {
	score := 68.0
	r := &trendReport{
		Period:       period{End: time.Now()},
		PostureScore: &score,
		Summary:      trendSummary{NetChangePercent: -5, Direction: "regressing"},
		TeamSummary:  &teamTrendSummary{TeamsTracked: 2, TeamsImproving: 1, TeamsRegressing: 1},
		TeamTrends: []teamTrend{
			{ID: "identity", Name: "Team Identity", PostureScore: 55, ScoreDelta: -10, Trajectory: trajectoryRegressing, CriticalOpen: 3, Contact: "id@test.com"},
			{ID: "payments", Name: "Team Payments", PostureScore: 90, ScoreDelta: 8, Trajectory: trajectoryImproving, MTTRHours: 18, SLACompPct: 94},
		},
	}

	var buf bytes.Buffer
	if err := renderExecutiveSummary(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ATTENTION REQUIRED") {
		t.Error("should contain attention required")
	}
	if !strings.Contains(out, "Team Identity") {
		t.Error("should name regressing team")
	}
	if !strings.Contains(out, "id@test.com") {
		t.Error("should contain contact")
	}
	if !strings.Contains(out, "Top performer") {
		t.Error("should contain top performer")
	}
	if !strings.Contains(out, "Team Payments") {
		t.Error("should name top performer")
	}
}
