package iam

import "strings"

// ARN represents a parsed AWS ARN.
// Format: arn:partition:service:region:account-id:resource
type ARN struct {
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
}

// ParseARN parses an AWS ARN string into its components.
// Returns zero-value ARN if the input is not a valid ARN.
func ParseARN(arn string) ARN {
	const minParts = 6
	if !strings.HasPrefix(arn, "arn:") {
		return ARN{}
	}
	parts := strings.SplitN(arn, ":", minParts)
	if len(parts) < minParts {
		return ARN{}
	}
	return ARN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		AccountID: parts[4],
		Resource:  parts[5],
	}
}

// ExtractAccountID returns the account ID component of an ARN.
// Returns empty string if the ARN is malformed or has no account
// (e.g. S3 bucket ARNs: arn:aws:s3:::bucket-name).
func ExtractAccountID(arn string) string {
	return ParseARN(arn).AccountID
}
