package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

type accessPresignedURL struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&accessPresignedURL{
		Definition: Build(
			WithID("ACCESS.009"),
			WithDescription("PHI bucket policy must restrict presigned URL access via s3:signatureAge or s3:authType condition"),
			WithSeverity(Medium),
			WithComplianceProfiles("hipaa"),
			WithComplianceRef("hipaa", "§164.312(a)(1)"),
			WithProfileRationale("hipaa", "Presigned URL restriction for PHI buckets"),
			WithProfileSeverityOverride("hipaa", Medium),
		),
	})
}

func (inv *accessPresignedURL) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		policyJSON := extractPolicyJSON(a)
		if policyJSON == "" {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: no bucket policy — presigned URLs are unrestricted", a.ID),
				"Add a bucket policy with a Deny statement using s3:signatureAge (max age in ms) or s3:authType (require REST-HEADER) to restrict presigned URL access.",
			)
		}

		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil || len(stmts) == 0 {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: bucket policy could not be parsed for presigned URL restrictions", a.ID),
				"Ensure the bucket policy is valid JSON with Statement entries.",
			)
		}

		for _, stmt := range stmts {
			if stmt.HasSignatureAgeGuardrail() || stmt.HasAuthTypeGuardrail() {
				goto nextAsset
			}
		}

		return inv.FailResult(
			fmt.Sprintf("Bucket %s: bucket policy does not contain s3:signatureAge or s3:authType guardrails — presigned URLs are unrestricted", a.ID),
			"Add a Deny statement with Condition NumericGreaterThan s3:signatureAge (e.g., 600000 for 10 minutes) or StringNotEquals s3:authType REST-HEADER to block presigned URL access.",
		)

	nextAsset:
	}
	return inv.PassResult()
}
