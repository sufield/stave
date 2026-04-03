package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
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
			WithSeverity(Critical),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(b)"),
			WithProfileRationale("hipaa", "All PHI access must be logged — logs cannot be obtained retroactively"),
		),
	})
}

// Evaluate checks that logging.target_bucket is set for every S3 bucket.
func (inv *auditServerLogging) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if props.Logging.TargetBucket == "" {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: server access logging is not enabled. Logs cannot be obtained retroactively from AWS — if a security incident occurs without logging enabled, no forensic evidence exists", a.ID),
				"Enable server access logging on the bucket. Set a target bucket in a separate account or with write-only permissions to prevent log tampering.",
			)
		}
	}

	return inv.PassResult()
}
