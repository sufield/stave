package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// controlsDenyNonTls checks that the bucket policy contains a Deny statement
// enforcing TLS via the aws:SecureTransport condition.
type controlsDenyNonTls struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&controlsDenyNonTls{
		Definition: NewDefinition(
			WithID("CONTROLS.004"),
			WithDescription("Bucket policy must deny non-TLS access (aws:SecureTransport=false). Note: S3 API endpoints enforce TLS 1.2 by default since February 2024, but HTTP endpoint access via website hosting remains possible"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(e)(2)(ii)"),
			WithProfileRationale("hipaa", "Encryption in transit — deny non-TLS access"),
		),
	})
}

// Evaluate checks that the bucket policy contains a Deny non-TLS statement.
func (ctl *controlsDenyNonTls) Evaluate(snap asset.Snapshot) Result {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, _ S3Properties) *Result {
		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil {
			return nil
		}

		for _, s := range stmts {
			if s.IsDenyNonTLS() {
				return nil
			}
		}

		r := ctl.FailResult(
			fmt.Sprintf("Bucket %s: no bucket policy statement denies non-TLS access — data in transit may be unencrypted when accessed via HTTP website endpoint", a.ID),
			"Add a Deny statement to the bucket policy with Condition {\"Bool\": {\"aws:SecureTransport\": \"false\"}} to block all HTTP access.",
		)
		return &r
	})
}
