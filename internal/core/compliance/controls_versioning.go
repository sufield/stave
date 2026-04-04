package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
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
			WithSeverity(policy.SeverityMedium),
			WithComplianceProfiles("hipaa", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(c)(1)"),
			WithProfileRationale("hipaa", "Integrity — versioning protects against accidental deletion"),
		),
	})
}

// Evaluate checks that versioning.enabled is true for every S3 bucket.
func (ctl *controlsVersioning) Evaluate(snap asset.Snapshot) Result {
	return ctl.evaluateS3Buckets(snap, func(a asset.Asset, props S3Properties) *Result {
		if !props.Versioning.Enabled {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: versioning is not enabled — accidental or malicious deletions cannot be recovered", a.ID),
				"Enable versioning on the bucket. For HIPAA workloads, also enable MFA Delete to prevent unauthorized permanent deletion of objects.",
			)
			return &r
		}
		return nil
	})
}
