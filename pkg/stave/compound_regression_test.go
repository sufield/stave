package stave_test

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/stave"
)

var (
	compoundNow = time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)
	chainsDir   = "../../internal/chains"
)

func TestCompoundRegression_RhinoAttachUserPolicy(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-disclosure-rhino-attachuserpolicy/observations",
		ChainsDir:    chainsDir,
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.Findings) == 0 {
		t.Fatal("expected findings, got 0")
	}

	if len(a.ChainFindings) == 0 {
		t.Fatal("expected chain findings, got 0")
	}

	found := false
	for _, c := range a.ChainFindings {
		if c.ChainID != "iam_privesc_by_attachment" {
			continue
		}
		found = true
		if c.Severity != "critical" {
			t.Errorf("chain severity = %s, want critical", c.Severity)
		}
		if len(c.ControlsFailing) == 0 {
			t.Error("expected failing controls in chain")
		}
		hasAttach := false
		for _, ctl := range c.ControlsFailing {
			if ctl == "CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001" {
				hasAttach = true
			}
		}
		if !hasAttach {
			t.Errorf("chain should include ATTACHUSERPOLICY.001, got %v", c.ControlsFailing)
		}
	}
	if !found {
		t.Error("expected iam_privesc_by_attachment chain, not found")
	}
}

func TestCompoundRegression_RhinoPassRoleCreateFunction(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-disclosure-rhino-passrole-createfunction/observations",
		ChainsDir:    chainsDir,
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.ChainFindings) == 0 {
		t.Fatal("expected chain findings, got 0")
	}

	found := false
	for _, c := range a.ChainFindings {
		if c.ChainID == "lambda_privesc" {
			found = true
			if c.Severity != "critical" {
				t.Errorf("chain severity = %s, want critical", c.Severity)
			}
		}
	}
	if !found {
		t.Error("expected lambda_privesc chain, not found")
	}
}

func TestCompoundRegression_IAMEscalateChainFires(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-forge-iam-escalate-chain-fail/observations",
		ControlsDir:  "../../testdata/e2e/e2e-forge-iam-escalate-chain-fail/controls",
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.Findings) == 0 {
		t.Fatal("expected findings from escalate chain fixture")
	}
}

func TestCompoundRegression_IAMEscalateChainSafe(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-forge-iam-escalate-chain-pass/observations",
		ControlsDir:  "../../testdata/e2e/e2e-forge-iam-escalate-chain-pass/controls",
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.Findings) != 0 {
		t.Errorf("expected 0 findings for safe fixture, got %d", len(a.Findings))
	}
}

func TestCompoundRegression_ChainMembershipOnFinding(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-disclosure-rhino-attachuserpolicy/observations",
		ChainsDir:    chainsDir,
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, f := range a.Findings {
		if f.ControlID == "CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001" {
			if len(f.ChainMembership) == 0 {
				t.Error("ATTACHUSERPOLICY finding should have chain membership")
			}
			for _, cm := range f.ChainMembership {
				if cm.ChainID == "iam_privesc_by_attachment" {
					if cm.ChainSeverity != "critical" {
						t.Errorf("chain membership severity = %s, want critical", cm.ChainSeverity)
					}
					return
				}
			}
			t.Error("ATTACHUSERPOLICY finding chain membership should include iam_privesc_by_attachment")
			return
		}
	}
	t.Error("ATTACHUSERPOLICY finding not found")
}

func TestCompoundRegression_CredentialManipulationTakeover(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-iam-escalate-credmanipulation-cluster/observations",
		ChainsDir:    chainsDir,
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.ChainFindings) == 0 {
		t.Fatal("expected chain findings, got 0")
	}

	found := false
	for _, c := range a.ChainFindings {
		if c.ChainID != "iam_credential_manipulation_takeover" {
			continue
		}
		found = true
		if c.Severity != "critical" {
			t.Errorf("chain severity = %s, want critical", c.Severity)
		}
		if len(c.ControlsFailing) < 2 {
			t.Errorf("expected ≥2 failing controls, got %d", len(c.ControlsFailing))
		}
	}
	if !found {
		t.Error("expected iam_credential_manipulation_takeover chain, not found")
	}
}

func TestCompoundRegression_CredentialManipulationSafe(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: "../../testdata/e2e/e2e-iam-escalate-credmanipulation-cluster/observations",
		ChainsDir:    chainsDir,
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, c := range a.ChainFindings {
		if c.ChainID != "iam_credential_manipulation_takeover" {
			continue
		}
		for _, ctl := range c.ControlsFailing {
			if ctl == "CTL.IAM.ESCALATE.CREATELOGINPROFILE.001" ||
				ctl == "CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001" ||
				ctl == "CTL.IAM.ESCALATE.RESYNCMFADEVICE.001" {
				continue
			}
			t.Errorf("unexpected control in chain: %s", ctl)
		}
	}
}

func TestCompoundRegression_SilentRiskControlNotInChain(t *testing.T) {
	a, err := stave.Apply(context.Background(), stave.Config{
		SnapshotsDir: lordofheavenSnapshots,
		EvalTime:     compoundNow,
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(a.SilentRiskControls) > 0 {
		for _, c := range a.ChainFindings {
			for _, sr := range a.SilentRiskControls {
				for _, failing := range c.ControlsFailing {
					if failing == sr.ControlID {
						t.Errorf("chain %s includes silent-risk control %s — chain should not assemble with unreliable members",
							c.ChainID, sr.ControlID)
					}
				}
			}
		}
	}
}
