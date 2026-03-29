package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// access001 checks that all four S3 Block Public Access flags are enabled
// at the bucket level. If account-level BPA is fully enabled but bucket-level
// is not set, severity downgrades to LOW.
type access001 struct {
	Definition
}

func init() {
	AccessRegistry.MustRegister(&access001{
		Definition: Build(
			WithID("ACCESS.001"),
			WithDescription("Block Public Access must be fully enabled at bucket level"),
			WithSeverity(Critical),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
			WithProfileRationale("hipaa", "Access control — Block Public Access prevents public exposure of ePHI"),
		),
	})
}

// Evaluate checks every S3 bucket asset in the snapshot for complete BPA enablement.
func (inv *access001) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		bpa := extractBPA(a)
		if bpa != nil && bpa.AllEnabled() {
			continue
		}

		// Check account-level BPA as a mitigating factor.
		if accountBPAFullyEnabled(a) {
			return Result{
				Pass:           false,
				ControlID:      inv.ID(),
				Severity:       Low,
				Finding:        fmt.Sprintf("Bucket %s: bucket-level BPA not fully enabled. Account-level BPA active — bucket-level is defense in depth", a.ID),
				Remediation:    "Enable all four Block Public Access flags on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
				ComplianceRefs: inv.ComplianceRefs(),
			}
		}

		return inv.FailResult(
			fmt.Sprintf("Bucket %s: Block Public Access is not fully enabled — publicly accessible objects may exist", a.ID),
			"Enable all four Block Public Access flags on the bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
		)
	}

	return inv.PassResult()
}

// --- Property extraction helpers ---

func isS3Bucket(a asset.Asset) bool {
	return a.Type.String() == "aws_s3_bucket"
}

func extractBPA(a asset.Asset) *asset.S3BlockPublicAccess {
	storage, ok := a.Properties["storage"].(map[string]any)
	if !ok {
		return nil
	}
	controls, ok := storage["controls"].(map[string]any)
	if !ok {
		return nil
	}
	block, ok := controls["public_access_block"].(map[string]any)
	if !ok {
		return nil
	}
	return &asset.S3BlockPublicAccess{
		BlockPublicACLs:       toBool(block["block_public_acls"]),
		IgnorePublicACLs:      toBool(block["ignore_public_acls"]),
		BlockPublicPolicy:     toBool(block["block_public_policy"]),
		RestrictPublicBuckets: toBool(block["restrict_public_buckets"]),
	}
}

func accountBPAFullyEnabled(a asset.Asset) bool {
	storage, ok := a.Properties["storage"].(map[string]any)
	if !ok {
		return false
	}
	controls, ok := storage["controls"].(map[string]any)
	if !ok {
		return false
	}
	return toBool(controls["account_public_access_fully_blocked"])
}

func toBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func extractPolicyJSON(a asset.Asset) string {
	s, _ := a.Properties["policy_json"].(string)
	return s
}
