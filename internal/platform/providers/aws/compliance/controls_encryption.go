package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// controlsEncryption checks that server-side encryption is enabled on every S3 bucket.
type controlsEncryption struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &controlsEncryption{
			Definition: core.NewDefinition(
				core.WithID("CONTROLS.001"),
				core.WithDescription("Server-side encryption (SSE) must be enabled"),
				core.WithSeverity(policy.SeverityHigh),
				core.WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(a)(2)(iv)"),
			),
		}
	})
}

// Evaluate checks that encryption.at_rest_enabled is true for every S3 bucket.
func (ctl *controlsEncryption) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if !props.Encryption.IsEnabled() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: server-side encryption is not enabled — data at rest is unprotected", a.ID),
				"Enable default encryption on the bucket using SSE-S3 (AES-256) or SSE-KMS. For HIPAA workloads, use SSE-KMS with a customer-managed key.",
			)
			return &r
		}
		return nil
	})
}
