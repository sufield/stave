package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// auditServerLogging checks that server access logging is enabled with a target bucket.
type auditServerLogging struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&auditServerLogging{
		Definition: NewDefinition(
			WithID("AUDIT.001"),
			WithDescription("Server access logging must be enabled with a configured target bucket"),
			WithSeverity(policy.SeverityCritical),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(b)"),
			WithProfileRationale("hipaa", "All PHI access must be logged — logs cannot be obtained retroactively"),
		),
	})
}

// Evaluate checks that logging.target_bucket is set for every S3 bucket.
func (ctl *auditServerLogging) Evaluate(snap asset.Snapshot) Outcome {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Outcome {
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
