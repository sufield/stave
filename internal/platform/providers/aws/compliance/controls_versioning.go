package compliance

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
	core "github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// controlsVersioning checks that versioning is enabled on every S3 bucket.
type controlsVersioning struct {
	core.Definition
}

func init() {
	core.RegisterControl(func() core.Control {
		return &controlsVersioning{
			Definition: core.NewDefinition(
				core.WithID("CONTROLS.002"),
				core.WithDescription("S3 bucket versioning must be enabled to protect data integrity"),
				core.WithSeverity(policy.SeverityMedium),
				core.WithComplianceProfiles("hipaa", "cis-s3"),
				core.WithComplianceRef("hipaa", "§164.312(c)(1)"),
				core.WithProfileRationale("hipaa", "Integrity — versioning protects against accidental deletion"),
			),
		}
	})
}

// Evaluate checks that versioning.enabled is true for every S3 bucket.
func (ctl *controlsVersioning) Evaluate(snap asset.Snapshot) core.Outcome {
	return evaluateS3Buckets(ctl.Definition, snap, func(a asset.Asset, props S3Properties) *core.Outcome {
		if !props.Versioning.IsEnabled() {
			r := ctl.FailResult(
				fmt.Sprintf("Bucket %s: versioning is not enabled — accidental or malicious deletions cannot be recovered", a.ID),
				"Enable versioning on the bucket. For HIPAA workloads, also enable MFA Delete to prevent unauthorized permanent deletion of objects.",
			)
			return &r
		}
		return nil
	})
}
