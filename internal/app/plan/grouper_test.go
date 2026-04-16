package plan

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func makeTestManifest() *teams.Manifest {
	return &teams.Manifest{
		OwnerTagKey:    "team",
		FallbackTagKey: "owner",
		Teams: []teams.Team{
			{ID: "alpha", DisplayName: "Team Alpha", Contact: "alpha@test.com",
				ResourcePatterns: []string{"arn:aws:s3:::alpha-*"}},
			{ID: "beta", DisplayName: "Team Beta", Contact: "beta@test.com",
				ResourcePatterns: []string{"arn:aws:s3:::beta-*"}},
		},
	}
}

func makeFinding(ctl, assetID string, sev policy.Severity, dwell float64) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			ControlName:     ctl + " name",
			AssetID:         asset.ID(assetID),
			ControlSeverity: sev,
			Evidence:        evaluation.Evidence{UnsafeDurationHours: dwell},
		},
	}
}

func TestGroup_AttributesToCorrectTeams(t *testing.T) {
	findings := []remediation.Finding{
		makeFinding("CTL.S3.001", "arn:aws:s3:::alpha-bucket", policy.SeverityCritical, 48),
		makeFinding("CTL.S3.002", "arn:aws:s3:::beta-data", policy.SeverityHigh, 24),
		makeFinding("CTL.S3.003", "arn:aws:s3:::alpha-logs", policy.SeverityMedium, 12),
	}

	p := Group(GroupInput{
		GeneratedAt: "2026-04-01T00:00:00Z",
		Assessment:  "test.json",
		Findings:    findings,
		Manifest:    makeTestManifest(),
		MinSeverity: "low",
	})

	if len(p.Teams) != 2 {
		t.Fatalf("teams = %d, want 2", len(p.Teams))
	}

	// Find alpha and beta.
	var alpha, beta *TeamPlan
	for i := range p.Teams {
		switch p.Teams[i].TeamID {
		case "alpha":
			alpha = &p.Teams[i]
		case "beta":
			beta = &p.Teams[i]
		}
	}
	if alpha == nil || beta == nil {
		t.Fatal("expected both alpha and beta teams")
	}
	if len(alpha.Findings) != 2 {
		t.Errorf("alpha findings = %d, want 2", len(alpha.Findings))
	}
	if len(beta.Findings) != 1 {
		t.Errorf("beta findings = %d, want 1", len(beta.Findings))
	}
}

func TestGroup_UnattributedFindings(t *testing.T) {
	findings := []remediation.Finding{
		makeFinding("CTL.S3.001", "arn:aws:s3:::unknown-bucket", policy.SeverityHigh, 24),
	}

	p := Group(GroupInput{
		GeneratedAt: "2026-04-01T00:00:00Z",
		Findings:    findings,
		Manifest:    makeTestManifest(),
		MinSeverity: "low",
	})

	if len(p.Unattributed) != 1 {
		t.Errorf("unattributed = %d, want 1", len(p.Unattributed))
	}
}

func TestGroup_SeverityFilter(t *testing.T) {
	findings := []remediation.Finding{
		makeFinding("CTL.A", "arn:aws:s3:::alpha-1", policy.SeverityCritical, 48),
		makeFinding("CTL.B", "arn:aws:s3:::alpha-2", policy.SeverityLow, 12),
	}

	p := Group(GroupInput{
		Findings:    findings,
		Manifest:    makeTestManifest(),
		MinSeverity: "high",
	})

	total := 0
	for _, tp := range p.Teams {
		total += len(tp.Findings)
	}
	if total != 1 {
		t.Errorf("findings after filter = %d, want 1 (low excluded)", total)
	}
}

func TestGroup_Deterministic(t *testing.T) {
	findings := []remediation.Finding{
		makeFinding("CTL.A", "arn:aws:s3:::alpha-1", policy.SeverityHigh, 48),
		makeFinding("CTL.B", "arn:aws:s3:::alpha-2", policy.SeverityCritical, 24),
		makeFinding("CTL.C", "arn:aws:s3:::beta-1", policy.SeverityMedium, 12),
	}

	p1 := Group(GroupInput{
		GeneratedAt: "2026-04-01T00:00:00Z",
		Findings:    findings,
		Manifest:    makeTestManifest(),
		MinSeverity: "low",
	})
	p2 := Group(GroupInput{
		GeneratedAt: "2026-04-01T00:00:00Z",
		Findings:    findings,
		Manifest:    makeTestManifest(),
		MinSeverity: "low",
	})

	var buf1, buf2 bytes.Buffer
	WriteMarkdown(&buf1, p1)
	WriteMarkdown(&buf2, p2)
	if buf1.String() != buf2.String() {
		t.Error("output is not deterministic — two runs produced different markdown")
	}
}

func TestWriteText_ContainsTeamName(t *testing.T) {
	p := &Plan{
		Teams: []TeamPlan{
			{
				TeamID:   "alpha",
				TeamName: "Team Alpha",
				Summary:  TeamSummary{Total: 1, Critical: 1},
				Findings: []PlanFinding{
					{Rank: 1, ControlID: "CTL.A.001", Severity: "critical", AssetID: "asset-1", DwellHours: 48},
				},
			},
		},
	}
	var buf bytes.Buffer
	WriteText(&buf, p)
	out := buf.String()
	if !strings.Contains(out, "TEAM ALPHA") {
		t.Error("text output should contain team name")
	}
	if !strings.Contains(out, "CTL.A.001") {
		t.Error("text output should contain control ID")
	}
}
