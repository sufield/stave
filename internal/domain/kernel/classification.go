package kernel

import "strings"

// ControlClass categorizes a control for downstream mapping.
type ControlClass int

const (
	ClassUnknown           ControlClass = iota
	ClassPublicExposure                 // Public access or write exposure
	ClassEncryptionMissing              // Missing or weak encryption at rest
	ClassBaselineViolation              // Configuration deviates from security baseline
)

// Classify returns the generic security class for this control ID.
func (id ControlID) Classify() ControlClass {
	s := strings.TrimSpace(id.String())
	switch {
	case strings.HasPrefix(s, "CTL.S3.PUBLIC"),
		strings.HasPrefix(s, "CTL.S3.ACL.WRITE"):
		return ClassPublicExposure
	case strings.HasPrefix(s, "CTL.S3.ENCRYPT"):
		return ClassEncryptionMissing
	case strings.HasPrefix(s, "CTL.S3."):
		return ClassBaselineViolation
	default:
		return ClassUnknown
	}
}
