package kernel

import "strings"

// ControlClass categorizes a control for downstream mapping.
type ControlClass int

const (
	ClassUnknown   ControlClass = iota
	ClassS3Public               // CTL.S3.PUBLIC.* or CTL.S3.ACL.WRITE.*
	ClassS3General              // CTL.S3.*
)

// Classify returns the class for this control ID.
func (id ControlID) Classify() ControlClass {
	s := strings.TrimSpace(id.String())
	switch {
	case strings.HasPrefix(s, "CTL.S3.PUBLIC"), strings.HasPrefix(s, "CTL.S3.ACL.WRITE"):
		return ClassS3Public
	case strings.HasPrefix(s, "CTL.S3."):
		return ClassS3General
	default:
		return ClassUnknown
	}
}
