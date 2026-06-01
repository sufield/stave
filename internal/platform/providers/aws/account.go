// Package aws holds AWS-specific identifier validation and parsing
// helpers. The kernel layer treats account IDs and resource URIs as
// vendor-agnostic values (kernel.AccountID, kernel.ResourceURI); the
// AWS-specific shape rules — 12-digit account IDs, arn:aws:iam::...
// ARN structure — live here so the core never grows a hard
// dependency on AWS conventions.
package aws

import (
	"regexp"
)

// awsAccountIDPattern matches the canonical 12-digit AWS account ID.
var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// awsAccountARNPattern matches arn:aws:iam::<12-digit>:(root|user/.*|role/.*).
// These three trailer shapes cover the principals AWS emits in resource
// policies; service principals (lambda.amazonaws.com) are not ARNs and
// shouldn't reach this validator.
var awsAccountARNPattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(root|user/.*|role/.*)$`)
