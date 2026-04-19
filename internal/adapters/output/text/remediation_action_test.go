package text

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestRemediationAction_ParameterizedCommandPreferred(t *testing.T) {
	f := &remediation.Finding{
		RemediationSpec: *policy.NewRemediationSpec("desc", "aws s3api put-public-access-block --bucket <name>", ""),
		RemediationPlan: &evaluation.RemediationPlan{
			Command: "aws s3api put-public-access-block --bucket gov-writable-bucket-1",
		},
	}
	got := remediationAction(f)
	want := "aws s3api put-public-access-block --bucket gov-writable-bucket-1"
	if got != want {
		t.Errorf("remediationAction = %q, want parameterized command %q", got, want)
	}
}

func TestRemediationAction_FallsBackToActionWhenNoPlan(t *testing.T) {
	f := &remediation.Finding{
		RemediationSpec: *policy.NewRemediationSpec("desc", "Enable S3 Public Access Block.", ""),
		RemediationPlan: nil,
	}
	got := remediationAction(f)
	want := "Enable S3 Public Access Block."
	if got != want {
		t.Errorf("remediationAction = %q, want %q (Action fallback)", got, want)
	}
}

func TestRemediationAction_FallsBackToActionWhenCommandEmpty(t *testing.T) {
	f := &remediation.Finding{
		RemediationSpec: *policy.NewRemediationSpec("desc", "Prose-only action.", ""),
		RemediationPlan: &evaluation.RemediationPlan{}, // Command empty
	}
	got := remediationAction(f)
	want := "Prose-only action."
	if got != want {
		t.Errorf("remediationAction = %q, want %q (Action fallback when Command empty)", got, want)
	}
}

func TestWriteFindingRemediation_TextShowsParameterized(t *testing.T) {
	f := &remediation.Finding{
		RemediationSpec: *policy.NewRemediationSpec(
			"Bucket has public read.",
			"aws s3api put-public-access-block --bucket <name>",
			"",
		),
		RemediationPlan: &evaluation.RemediationPlan{
			Command: "aws s3api put-public-access-block --bucket gov-writable-bucket-1",
		},
	}
	var sb strings.Builder
	d := &drawer{w: &sb}
	writeFindingRemediation(d, f)
	out := sb.String()
	if !strings.Contains(out, "--bucket gov-writable-bucket-1") {
		t.Errorf("text output must render parameterized command, got:\n%s", out)
	}
	if strings.Contains(out, "--bucket <name>") {
		t.Errorf("text output must not render template when parameterized is available, got:\n%s", out)
	}
}
