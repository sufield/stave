package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

const awsManagedS3KeyAlias = "alias/aws/s3"

// controlsKmsCmk checks that SSE uses KMS with a customer-managed key (CMK),
// not the AWS-managed alias/aws/s3 key.
type controlsKmsCmk struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &controlsKmsCmk{
			Definition: core.NewDefinition(
				core.WithID("CONTROLS.001.STRICT"),
				core.WithDescription("Server-side encryption must use SSE-KMS with a customer-managed key (CMK)"),
				core.WithSeverity(policy.SeverityCritical),
				core.WithComplianceProfiles("hipaa"),
				core.WithComplianceRef("hipaa", "§164.312(a)(2)(iv)"),
				core.WithProfileRationale("hipaa", "CMK required for key revocation during breach response"),
			),
		}
	})
}

// Evaluate checks that encryption uses aws:kms with a non-AWS-managed key.
func (ctl *controlsKmsCmk) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if !props.Encryption.IsEnabled() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: encryption is not enabled — CMK requirement cannot be met without SSE", a.ID),
				"Enable SSE-KMS with a customer-managed CMK. Do not use the AWS-managed key (alias/aws/s3).",
			)
			return &r
		}

		if !props.Encryption.IsKMS() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: encryption algorithm is %q, not aws:kms — SSE-KMS with CMK is required for HIPAA", a.ID, props.Encryption.Algorithm),
				"Change the default encryption to SSE-KMS (aws:kms) with a customer-managed CMK.",
			)
			return &r
		}

		keyID := props.Encryption.KMSMasterKeyID
		if keyID == "" {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: SSE-KMS is enabled but no KMS key ID is set — likely using the AWS-managed default", a.ID),
				"Specify a customer-managed CMK ARN in the bucket's default encryption configuration.",
			)
			return &r
		}

		if props.Encryption.IsAWSManagedKey() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: SSE-KMS uses the AWS-managed key (%s). CMK required for key revocation during breach response — AWS-managed keys cannot be revoked", a.ID, awsManagedS3KeyAlias),
				"Replace the AWS-managed key with a customer-managed CMK. Create a KMS key with key rotation enabled, then set it as the bucket's default encryption key.",
			)
			return &r
		}

		return nil
	})
}
