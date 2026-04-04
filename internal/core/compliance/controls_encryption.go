package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// controlsEncryption checks that server-side encryption is enabled on every S3 bucket.
type controlsEncryption struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&controlsEncryption{
		Definition: NewDefinition(
			WithID("CONTROLS.001"),
			WithDescription("Server-side encryption (SSE) must be enabled"),
			WithSeverity(policy.SeverityHigh),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(2)(iv)"),
		),
	})
}

// Evaluate checks that encryption.at_rest_enabled is true for every S3 bucket.
func (ctl *controlsEncryption) Evaluate(snap asset.Snapshot) Result {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Result {
		if !props.Encryption.AtRestEnabled {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: server-side encryption is not enabled — data at rest is unprotected", a.ID),
				"Enable default encryption on the bucket using SSE-S3 (AES-256) or SSE-KMS. For HIPAA workloads, use SSE-KMS with a customer-managed key.",
			)
			return &r
		}
		return nil
	})
}
