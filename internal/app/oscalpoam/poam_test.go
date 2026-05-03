package oscalpoam

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestGenerate_FindingMapsToItem(t *testing.T) {
	slaHours := 72.0
	findings := []remediation.Finding{
		func() remediation.Finding {
			ev := evaluation.Finding{
				ControlID:       kernel.ControlID("CTL.S3.PUBLIC.001"),
				ControlName:     "S3 public access",
				AssetID:         asset.ID("arn:aws:s3:::prod-bucket"),
				ControlSeverity: policy.SeverityHigh,
			}
			ev.RehydrateSLA(&slaHours, false, nil, 0, "")
			return remediation.Finding{Finding: ev}
		}(),
	}

	poam := Generate(Input{
		Findings:   findings,
		SystemUUID: "test-system",
		Now:        time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
	})

	if len(poam.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(poam.Items))
	}

	item := poam.Items[0]
	if len(item.RelatedControls) != 1 || item.RelatedControls[0].ControlID != "CTL.S3.PUBLIC.001" {
		t.Error("related control not mapped correctly")
	}
	if item.ScheduledCompletionDate == "" {
		t.Error("SLA deadline should map to scheduled-completion-date")
	}
	if poam.Metadata.OSCALVersion != "1.1.2" {
		t.Errorf("OSCAL version = %s, want 1.1.2", poam.Metadata.OSCALVersion)
	}
}

func TestGenerate_DeterministicUUID(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				ControlID: "CTL.A.001",
				AssetID:   "asset1",
			},
		},
	}

	p1 := Generate(Input{Findings: findings, SystemUUID: "sys", Now: time.Now()})
	p2 := Generate(Input{Findings: findings, SystemUUID: "sys", Now: time.Now()})

	if p1.Items[0].UUID != p2.Items[0].UUID {
		t.Error("UUID should be deterministic for same inputs")
	}
}
