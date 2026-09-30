package eval

import (
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

type mockSanitizer struct {
	noopSanitizer
}

func (mockSanitizer) ID(s string) string {
	if s == "sensitive-arn" {
		return "masked-id"
	}
	return s
}

func TestBugHunt_SanitizeFinding_SanitizesRemediationCommand(t *testing.T) {
	f := remediation.Finding{
		AssetID: "sensitive-arn",
		RemediationSpec: policy.RemediationSpec{
			Action: "aws s3api put-bucket-versioning --bucket <id>",
		},
		RemediationPlan: &evaluation.RemediationPlan{
			Command: "aws s3api put-bucket-versioning --bucket sensitive-arn",
		},
	}

	sanitized := sanitizeFinding(&f, mockSanitizer{})

	if sanitized.RemediationPlan == nil {
		t.Fatal("expected RemediationPlan to be present")
	}

	// Under the buggy code: RemediationPlan.Command is not sanitized,
	// so it still contains "sensitive-arn".
	if strings.Contains(sanitized.RemediationPlan.Command, "sensitive-arn") {
		t.Errorf("sanitization leak: command still contains sensitive asset ID: %q", sanitized.RemediationPlan.Command)
	}

	if !strings.Contains(sanitized.RemediationPlan.Command, "masked-id") {
		t.Errorf("expected command to contain masked ID, got: %q", sanitized.RemediationPlan.Command)
	}
}
