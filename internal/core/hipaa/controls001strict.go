package hipaa

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

const awsManagedS3KeyAlias = "alias/aws/s3"

// controls001strict checks that SSE uses KMS with a customer-managed key (CMK),
// not the AWS-managed alias/aws/s3 key.
type controls001strict struct {
	Definition
}

func init() {
	ControlsRegistry.MustRegister(&controls001strict{
		Definition: Build(
			WithID("CONTROLS.001.STRICT"),
			WithDescription("Server-side encryption must use SSE-KMS with a customer-managed key (CMK)"),
			WithSeverity(Critical),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(a)(2)(iv)"),
			WithProfileRationale("hipaa", "CMK required for key revocation during breach response"),
		),
	})
}

// Evaluate checks that encryption uses aws:kms with a non-AWS-managed key.
func (inv *controls001strict) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		enc := encryptionMap(a)
		if enc == nil || !toBool(enc["at_rest_enabled"]) {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: encryption is not enabled — CMK requirement cannot be met without SSE", a.ID),
				"Enable SSE-KMS with a customer-managed CMK. Do not use the AWS-managed key (alias/aws/s3).",
			)
		}

		algorithm := toString(enc["algorithm"])
		if !strings.EqualFold(algorithm, "aws:kms") {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: encryption algorithm is %q, not aws:kms — SSE-KMS with CMK is required for HIPAA", a.ID, algorithm),
				"Change the default encryption to SSE-KMS (aws:kms) with a customer-managed CMK.",
			)
		}

		keyID := toString(enc["kms_master_key_id"])
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
