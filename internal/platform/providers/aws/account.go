// Package aws holds AWS-specific identifier validation and parsing
// helpers. The kernel layer treats account IDs and resource URIs as
// vendor-agnostic values (kernel.AccountID, kernel.ResourceURI); the
// AWS-specific shape rules — 12-digit account IDs, arn:aws:iam::...
// ARN structure — live here so the core never grows a hard
// dependency on AWS conventions.
package aws

import (
	"fmt"
	"regexp"

	"github.com/sufield/stave/internal/core/kernel"
)

// awsAccountIDPattern matches the canonical 12-digit AWS account ID.
var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// awsAccountARNPattern matches arn:aws:iam::<12-digit>:(root|user/.*|role/.*).
// These three trailer shapes cover the principals AWS emits in resource
// policies; service principals (lambda.amazonaws.com) are not ARNs and
// shouldn't reach this validator.
var awsAccountARNPattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(root|user/.*|role/.*)$`)

// ValidateAccountID enforces the AWS-specific 12-digit account ID
// rule. Callers in the AWS adapter use this when interpreting an
// observation that claims AWS provenance; the kernel itself accepts
// any structurally-sound AccountID.
func ValidateAccountID(id kernel.AccountID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	if !awsAccountIDPattern.MatchString(string(id)) {
		return fmt.Errorf("invalid AWS account ID %q: must be exactly 12 digits", string(id))
	}
	return nil
}

// ParseAccountID returns a kernel.AccountID after enforcing the
// AWS-specific 12-digit shape.
func ParseAccountID(raw string) (kernel.AccountID, error) {
	id := kernel.AccountID(raw)
	if err := ValidateAccountID(id); err != nil {
		return "", err
	}
	return id, nil
}

// ValidateAccountARN enforces the AWS IAM ARN shape on a kernel
// ResourceURI. Used at trust boundaries where the value is known to
// be an AWS account ARN; non-AWS schemes (gcp:, azure:) are rejected.
func ValidateAccountARN(uri kernel.ResourceURI) error {
	if err := uri.Validate(); err != nil {
		return err
	}
	if !awsAccountARNPattern.MatchString(string(uri)) {
		return fmt.Errorf("invalid AWS account ARN %q: expected arn:aws:iam::<12-digit>:(root|user/<n>|role/<n>)", string(uri))
	}
	return nil
}

// ParseAccountARN returns a kernel.ResourceURI after enforcing the
// AWS IAM ARN shape.
func ParseAccountARN(raw string) (kernel.ResourceURI, error) {
	uri := kernel.ResourceURI(raw)
	if err := ValidateAccountARN(uri); err != nil {
		return "", err
	}
	return uri, nil
}

// ExtractAccountID pulls the 12-digit account segment out of an AWS
// IAM ARN. Returns ("", false) when the URI is not an AWS account
// ARN. The kernel does not own this logic — knowledge of AWS's
// arn:aws:iam::<account>:... layout belongs in the provider adapter.
func ExtractAccountID(uri kernel.ResourceURI) (kernel.AccountID, bool) {
	matches := awsAccountARNPattern.FindStringSubmatch(string(uri))
	if matches == nil {
		return "", false
	}
	return kernel.AccountID(matches[1]), true
}
