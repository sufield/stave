package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// accessBlockPublic checks that all four S3 Block Public Access flags are enabled
// at the bucket level. If account-level BPA is fully enabled but bucket-level
// is not set, severity downgrades to LOW.
type accessBlockPublic struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessBlockPublic{
		Definition: NewDefinition(
			WithID("ACCESS.001"),
			WithDescription("Block Public Access must be fully enabled at bucket level"),
			WithSeverity(policy.SeverityCritical),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
			WithProfileRationale("hipaa", "Access control — Block Public Access prevents public exposure of ePHI"),
		),
	})
}

// Evaluate checks every S3 bucket asset in the snapshot for complete BPA enablement.
func (ctl *accessBlockPublic) Evaluate(snap asset.Snapshot) Result {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Result {
		if props.Controls.PublicAccessBlock.Present && props.Controls.PublicAccessBlock.AllEnabled() {
			return nil
		}

		// Check account-level BPA as a mitigating factor.
		if props.Controls.AccountPublicAccessFullyBlocked {
			r := Result{
				Pass:           false,
				ControlID:      ctl.ID(),
				Severity:       policy.SeverityLow,
				Finding:        fmt.Sprintf("Bucket %s: bucket-level BPA not fully enabled. Account-level BPA active — bucket-level is defense in depth", a.ID),
				Remediation:    "Enable all four Block Public Access flags on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
				ComplianceRefs: ctl.ComplianceRefs(),
			}
			return &r
		}

		r := ctl.FailResult(
			fmt.Sprintf("Bucket %s: Block Public Access is not fully enabled — publicly accessible objects may exist", a.ID),
			"Enable all four Block Public Access flags on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
		)
		return &r
	})
}

func extractPolicyJSON(a asset.Asset) string {
	return ParseS3Properties(a).PolicyJSON
}
