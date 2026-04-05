package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type auditObjectLogging struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&auditObjectLogging{
		Definition: NewDefinition(
			WithID("AUDIT.002"),
			WithDescription("CloudTrail S3 object-level data event logging must be enabled"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(b)"),
			WithProfileRationale("hipaa", "Object-level logging for PHI access audit trail"),
			WithProfileSeverityOverride("hipaa", policy.SeverityHigh),
		),
	})
}

func (ctl *auditObjectLogging) Evaluate(snap asset.Snapshot) Outcome {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Outcome {
		if !props.Logging.ObjectLevelLogging.Enabled {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: CloudTrail S3 object-level data event logging is not enabled — no forensic evidence for PHI access", a.ID),
				"Configure a CloudTrail trail with a data event selector for AWS::S3::Object covering this bucket. Use aws cloudtrail put-event-selectors.",
			)
			return &r
		}
		return nil
	})
}
