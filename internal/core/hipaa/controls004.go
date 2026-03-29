package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// controls004 checks that the bucket policy contains a Deny statement
// enforcing TLS via the aws:SecureTransport condition.
type controls004 struct {
	Definition
}

func init() {
	ControlsRegistry.MustRegister(&controls004{
		Definition: Build(
			WithID("CONTROLS.004"),
			WithDescription("Bucket policy must deny non-TLS access (aws:SecureTransport=false). Note: S3 API endpoints enforce TLS 1.2 by default since February 2024, but HTTP endpoint access via website hosting remains possible"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(e)(2)(ii)"),
		),
	})
}

// Evaluate checks that the bucket policy contains a Deny non-TLS statement.
func (inv *controls004) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil {
			continue
		}

		hasDenyNonTLS := false
		for _, s := range stmts {
			if s.IsDenyNonTLS() {
				hasDenyNonTLS = true
				break
			}
		}

		if !hasDenyNonTLS {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: no bucket policy statement denies non-TLS access — data in transit may be unencrypted when accessed via HTTP website endpoint", a.ID),
				"Add a Deny statement to the bucket policy with Condition {\"Bool\": {\"aws:SecureTransport\": \"false\"}} to block all HTTP access.",
			)
		}
	}

	return inv.PassResult()
}
