package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type auditObjectLogging struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &auditObjectLogging{
			Definition: core.NewDefinition(
				core.WithID("AUDIT.002"),
				core.WithDescription("CloudTrail S3 object-level data event logging must be enabled"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa"),
				core.WithComplianceRef("hipaa", "§164.312(b)"),
				core.WithProfileRationale("hipaa", "Object-level logging for PHI access audit trail"),
				core.WithProfileSeverityOverride("hipaa", policy.SeverityHigh),
			),
		}
	})
}

func (ctl *auditObjectLogging) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
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
