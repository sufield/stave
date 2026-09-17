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
			ev.RehydrateSLA(evaluation.SLAState{Deadline: &slaHours})
			return remediation.Finding{Finding: ev}
		}(),
	}

	poam := Generate(Input{
		Findings:   findings,
		SystemUUID: "test-system",
		EvalTime:   time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC),
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
			ControlID: "CTL.A.001",
			AssetID:   "asset1",
		},
	}

	p1 := Generate(Input{Findings: findings, SystemUUID: "sys", EvalTime: time.Now()})
	p2 := Generate(Input{Findings: findings, SystemUUID: "sys", EvalTime: time.Now()})

	if p1.Items[0].UUID != p2.Items[0].UUID {
		t.Error("UUID should be deterministic for same inputs")
	}
}

func TestPOAMItems_DomainMethods(t *testing.T) {
	items := POAMItems{
		{
			UUID:            "i1",
			RelatedControls: []RelatedCtl{{ControlID: "CTL.A.001"}},
		},
		{
			UUID:            "i2",
			RelatedControls: []RelatedCtl{{ControlID: "CTL.B.002"}},
		},
		{
			UUID:            "i3",
			RelatedControls: []RelatedCtl{{ControlID: "CTL.A.001"}},
		},
	}

	if items.Len() != 3 {
		t.Errorf("items.Len() = %d, want 3", items.Len())
	}

	ctlA := items.ByControl(kernel.ControlID("CTL.A.001"))
	if ctlA.Len() != 2 {
		t.Errorf("ByControl(CTL.A.001).Len() = %d, want 2", ctlA.Len())
	}

	var empty POAMItems
	if empty.Len() != 0 {
		t.Errorf("empty.Len() = %d, want 0", empty.Len())
	}
	if empty.ByControl(kernel.ControlID("CTL.A.001")) != nil {
		t.Error("empty.ByControl() should return nil")
	}
}
