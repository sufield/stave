package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// controlsVersioning checks that versioning is enabled on every S3 bucket.
type controlsVersioning struct {
	Definition
}

func init() {
	ControlRegistry.MustRegister(&controlsVersioning{
		Definition: NewDefinition(
			WithID("CONTROLS.002"),
			WithDescription("S3 bucket versioning must be enabled to protect data integrity"),
			WithSeverity(Medium),
			WithComplianceProfiles("hipaa", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(c)(1)"),
			WithProfileRationale("hipaa", "Integrity — versioning protects against accidental deletion"),
		),
	})
}

// Evaluate checks that versioning.enabled is true for every S3 bucket.
func (inv *controlsVersioning) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		props := ParseS3Properties(a)
		if !props.Versioning.Enabled {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: versioning is not enabled — accidental or malicious deletions cannot be recovered", a.ID),
				"Enable versioning on the bucket. For HIPAA workloads, also enable MFA Delete to prevent unauthorized permanent deletion of objects.",
			)
		}
	}

	return inv.PassResult()
}
