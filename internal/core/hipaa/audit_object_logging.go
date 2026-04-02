package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

type auditObjectLogging struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&auditObjectLogging{
		Definition: Build(
			WithID("AUDIT.002"),
			WithDescription("CloudTrail S3 object-level data event logging must be enabled"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(b)"),
			WithProfileRationale("hipaa", "Object-level logging for PHI access audit trail"),
			WithProfileSeverityOverride("hipaa", High),
		),
	})
}

func (inv *auditObjectLogging) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if !props.Logging.ObjectLevelLogging.Enabled {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: CloudTrail S3 object-level data event logging is not enabled — no forensic evidence for PHI access", a.ID),
				"Configure a CloudTrail trail with a data event selector for AWS::S3::Object covering this bucket. Use aws cloudtrail put-event-selectors.",
			)
		}
	}
	return inv.PassResult()
}
