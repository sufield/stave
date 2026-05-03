package iam

import "strings"

// IsARN reports whether the given asset identifier is shaped like
// an AWS ARN (starts with "arn:aws:"). Lives in the AWS provider
// because the prefix is vendor-specific; callers in the adapter
// layer that already know they are formatting AWS resource output
// import this directly.
func IsARN(id string) bool {
	return strings.HasPrefix(id, "arn:aws:")
}

// Region returns the region component of an AWS ARN, or "" when
// the input is not an ARN or its format omits the region segment.
// AWS ARNs follow arn:aws:<service>:<region>:<account>:<resource>;
// region is the fourth colon-separated field.
func Region(id string) string {
	if !IsARN(id) {
		return ""
	}
	parts := strings.SplitN(id, ":", 6)
	if len(parts) < 6 {
		return ""
	}
	return parts[3]
}
