package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// auditServerLogging checks that server access logging is enabled with a target bucket.
type auditServerLogging struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &auditServerLogging{
			Definition: core.NewDefinition(
				core.WithID("AUDIT.001"),
				core.WithDescription("Server access logging must be enabled with a configured target bucket"),
				core.WithSeverity(policy.SeverityCritical),
				core.WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(b)"),
				core.WithProfileRationale("hipaa", "All PHI access must be logged — logs cannot be obtained retroactively"),
			),
		}
	})
}

// Evaluate checks that logging.target_bucket is set for every S3 bucket.
func (ctl *auditServerLogging) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if props.Logging.TargetBucket == "" {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: server access logging is not enabled. Logs cannot be obtained retroactively from AWS — if a security incident occurs without logging enabled, no forensic evidence exists", a.ID),
				"Enable server access logging on the bucket. Set a target bucket in a separate account or with write-only permissions to prevent log tampering.",
			)
			return &r
		}
		return nil
	})
}
