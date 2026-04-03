package controldef

import "github.com/sufield/stave/internal/core/kernel"

// DefaultRemediationForClass returns fallback remediation guidance
// for a control class when no YAML-defined remediation exists.
func DefaultRemediationForClass(class kernel.ControlClass) RemediationSpec {
	switch class {
	case kernel.ClassPublicExposure:
		return RemediationSpec{
			Description: "Resource is exposed to the public internet.",
			Action:      "Restrict access to authorized principals only.",
		}
	case kernel.ClassEncryptionMissing:
		return RemediationSpec{
			Description: "Resource data is not encrypted at rest.",
			Action:      "Enable server-side encryption using a managed key.",
		}
	case kernel.ClassBaselineViolation:
		return RemediationSpec{
			Description: "Resource configuration deviates from security baseline.",
			Action:      "Review the misconfigured properties and revert to compliant values.",
		}
	default:
		return RemediationSpec{
			Description: "Security control violation detected.",
			Action:      "Review the finding evidence and remediate the configuration.",
		}
	}
}
