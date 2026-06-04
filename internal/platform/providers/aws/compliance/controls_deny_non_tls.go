package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// controlsDenyNonTLS checks that the bucket policy contains a Deny statement
// enforcing TLS via the aws:SecureTransport condition.
type controlsDenyNonTLS struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &controlsDenyNonTLS{
			Definition: core.NewDefinition(
				core.WithID("CONTROLS.004"),
				core.WithDescription("Bucket policy must deny non-TLS access (aws:SecureTransport=false). Note: S3 API endpoints enforce TLS 1.2 by default since February 2024, but HTTP endpoint access via website hosting remains possible"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(e)(2)(ii)"),
				core.WithProfileRationale("hipaa", "Encryption in transit — deny non-TLS access"),
			),
		}
	})
}

// Evaluate checks that the bucket policy contains a Deny non-TLS statement.
func (ctl *controlsDenyNonTLS) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, _ S3Properties) *core.Outcome {
		policyJSON := extractPolicyJSON(a)
		stmts, err := ParsePolicyStatements(policyJSON)
		if err != nil {
			// Present-but-unparseable policy: cannot confirm a Deny-non-TLS
			// guardrail exists — flag rather than silently pass.
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: bucket policy is present but could not be parsed (%v); cannot verify a Deny-non-TLS guardrail is present", a.ID, err),
				"Fix the malformed bucket policy JSON so the TLS guardrail can be evaluated; an unparseable policy cannot be proven to enforce TLS.",
			)
			return &r
		}

		// Index iteration to avoid the per-iteration copy of the
		// typed PolicyStatement (192 bytes after Subset B).
		for i := range stmts {
			if stmts[i].IsDenyNonTLS() {
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
