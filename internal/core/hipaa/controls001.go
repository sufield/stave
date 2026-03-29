package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// controls001 checks that server-side encryption is enabled on every S3 bucket.
type controls001 struct {
	Definition
}

func init() {
	ControlsRegistry.MustRegister(&controls001{
		Definition: Build(
			WithID("CONTROLS.001"),
			WithDescription("Server-side encryption (SSE) must be enabled"),
			WithSeverity(High),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(a)(2)(iv)"),
		),
	})
}

// Evaluate checks that encryption.at_rest_enabled is true for every S3 bucket.
func (inv *controls001) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		enc := encryptionMap(a)
		if enc == nil || !toBool(enc["at_rest_enabled"]) {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: server-side encryption is not enabled — data at rest is unprotected", a.ID),
				"Enable default encryption on the bucket using SSE-S3 (AES-256) or SSE-KMS. For HIPAA workloads, use SSE-KMS with a customer-managed key.",
			)
		}
	}

	return inv.PassResult()
}
