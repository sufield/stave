package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// retentionObjectLock checks that Object Lock is enabled and evaluates the lock mode.
type retentionObjectLock struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&retentionObjectLock{
		Definition: NewDefinition(
			WithID("RETENTION.002"),
			WithDescription("Object Lock must be enabled for PHI retention (6-year HIPAA minimum)"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.316(b)(2)"),
			WithProfileRationale("hipaa", "6-year PHI retention via Object Lock"),
		),
	})
}

// Evaluate checks Object Lock status and mode, returning severity based
// on the actual lock configuration rather than a hardcoded value.
func (ctl *retentionObjectLock) Evaluate(snap asset.Snapshot) Result {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Result {
		if !props.ObjectLock.Enabled {
			r := Result{
				Pass:           false,
				ControlID:      ctl.ID(),
				Severity:       policy.SeverityCritical,
				Finding:        fmt.Sprintf("Bucket %s: Object Lock is not enabled — objects can be deleted or overwritten, violating the 6-year HIPAA PHI retention requirement", a.ID),
				Remediation:    "Enable Object Lock on the bucket. Note: Object Lock can only be enabled at bucket creation time. You may need to create a new bucket with Object Lock enabled and migrate objects.",
				ComplianceRefs: ctl.ComplianceRefs(),
			}
			return &r
		}

		switch props.ObjectLock.Mode {
		case ObjectLockModeCompliance:
			return nil // strongest protection, pass
		case ObjectLockModeGovernance:
			r := Result{
				Pass:           false,
				ControlID:      ctl.ID(),
				Severity:       policy.SeverityHigh,
				Finding:        fmt.Sprintf("Bucket %s: Object Lock is in Governance mode — users with s3:BypassGovernanceRetention permission can override retention and delete objects. For HIPAA PHI, Compliance mode provides the strongest protection", a.ID),
				Remediation:    "Switch Object Lock from Governance mode to Compliance mode. In Compliance mode, no user (including root) can delete objects before the retention period expires.",
				ComplianceRefs: ctl.ComplianceRefs(),
			}
			return &r
		default:
			// Object Lock enabled but mode not set or unrecognized
			r := Result{
				Pass:           false,
				ControlID:      ctl.ID(),
				Severity:       policy.SeverityHigh,
				Finding:        fmt.Sprintf("Bucket %s: Object Lock is enabled but no retention mode is configured (mode=%q)", a.ID, props.ObjectLock.Mode),
				Remediation:    "Configure a default retention policy with Compliance mode and a retention period of at least 6 years (2190 days) for HIPAA PHI.",
				ComplianceRefs: ctl.ComplianceRefs(),
			}
			return &r
		}
	})
}
