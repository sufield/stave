package compliance

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

const awsManagedS3KeyAlias = "alias/aws/s3"

// controlsKmsCmk checks that SSE uses KMS with a customer-managed key (CMK),
// not the AWS-managed alias/aws/s3 key.
type controlsKmsCmk struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&controlsKmsCmk{
		Definition: NewDefinition(
			WithID("CONTROLS.001.STRICT"),
			WithDescription("Server-side encryption must use SSE-KMS with a customer-managed key (CMK)"),
			WithSeverity(policy.SeverityCritical),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(a)(2)(iv)"),
			WithProfileRationale("hipaa", "CMK required for key revocation during breach response"),
		),
	})
}

// Evaluate checks that encryption uses aws:kms with a non-AWS-managed key.
func (inv *controlsKmsCmk) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if !props.Encryption.AtRestEnabled {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: encryption is not enabled — CMK requirement cannot be met without SSE", a.ID),
				"Enable SSE-KMS with a customer-managed CMK. Do not use the AWS-managed key (alias/aws/s3).",
			)
		}

		if !strings.EqualFold(props.Encryption.Algorithm, "aws:kms") {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: encryption algorithm is %q, not aws:kms — SSE-KMS with CMK is required for HIPAA", a.ID, props.Encryption.Algorithm),
				"Change the default encryption to SSE-KMS (aws:kms) with a customer-managed CMK.",
			)
		}

		keyID := props.Encryption.KMSMasterKeyID
		if keyID == "" {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: SSE-KMS is enabled but no KMS key ID is set — likely using the AWS-managed default", a.ID),
				"Specify a customer-managed CMK ARN in the bucket's default encryption configuration.",
			)
		}

		if strings.EqualFold(keyID, awsManagedS3KeyAlias) || strings.HasSuffix(strings.ToLower(keyID), "/"+strings.ToLower(awsManagedS3KeyAlias)) {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: SSE-KMS uses the AWS-managed key (%s). CMK required for key revocation during breach response — AWS-managed keys cannot be revoked", a.ID, awsManagedS3KeyAlias),
				"Replace the AWS-managed key with a customer-managed CMK. Create a KMS key with key rotation enabled, then set it as the bucket's default encryption key.",
			)
		}
	}

	return inv.PassResult()
}
