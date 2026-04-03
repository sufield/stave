package compliance

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Object Lock mode constants.
const (
	lockModeCompliance = "COMPLIANCE"
	lockModeGovernance = "GOVERNANCE"
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
func (inv *retentionObjectLock) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if !props.ObjectLock.Enabled {
			return Result{
				Pass:           false,
				ControlID:      inv.ID(),
				Severity:       policy.SeverityCritical,
				Finding:        fmt.Sprintf("Bucket %s: Object Lock is not enabled — objects can be deleted or overwritten, violating the 6-year HIPAA PHI retention requirement", a.ID),
				Remediation:    "Enable Object Lock on the bucket. Note: Object Lock can only be enabled at bucket creation time. You may need to create a new bucket with Object Lock enabled and migrate objects.",
				ComplianceRefs: inv.ComplianceRefs(),
			}
		}

		mode := strings.ToUpper(props.ObjectLock.Mode)
		switch mode {
		case lockModeCompliance:
			continue // strongest protection, pass
		case lockModeGovernance:
			return Result{
				Pass:           false,
				ControlID:      inv.ID(),
				Severity:       policy.SeverityHigh,
				Finding:        fmt.Sprintf("Bucket %s: Object Lock is in Governance mode — users with s3:BypassGovernanceRetention permission can override retention and delete objects. For HIPAA PHI, Compliance mode provides the strongest protection", a.ID),
				Remediation:    "Switch Object Lock from Governance mode to Compliance mode. In Compliance mode, no user (including root) can delete objects before the retention period expires.",
				ComplianceRefs: inv.ComplianceRefs(),
			}
		default:
			// Object Lock enabled but mode not set or unrecognized
			return Result{
				Pass:           false,
				ControlID:      inv.ID(),
				Severity:       policy.SeverityHigh,
				Finding:        fmt.Sprintf("Bucket %s: Object Lock is enabled but no retention mode is configured (mode=%q)", a.ID, props.ObjectLock.Mode),
				Remediation:    "Configure a default retention policy with Compliance mode and a retention period of at least 6 years (2190 days) for HIPAA PHI.",
				ComplianceRefs: inv.ComplianceRefs(),
			}
		}
	}

	return inv.PassResult()
}
