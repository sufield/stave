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
	if !strings.HasPrefix(arn, "arn:") {
		return ARN{}
	}
	remaining := arn[4:] // skip "arn:"
	var found bool

	var partition, service, region, accountID, resource string

	partition, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return ARN{}
	}

	service, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return ARN{}
	}

	region, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return ARN{}
	}

	accountID, resource, found = strings.Cut(remaining, ":")
	if !found {
		accountID = remaining
		resource = ""
	}

	return ARN{
		Partition: partition,
		Service:   service,
		Region:    region,
		AccountID: accountID,
		Resource:  resource,
	}
}

// ExtractAccountID returns the account ID component of an ARN.
// Returns empty string if the ARN is malformed or has no account
// (e.g. S3 bucket ARNs: arn:aws:s3:::bucket-name).
func ExtractAccountID(arn string) string {
	return ParseARN(arn).AccountID
}
