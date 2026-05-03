package iam

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/access"
)

// Type aliases: the canonical home for these data types is
// internal/core/access (vendor-neutral). Aliases here keep existing
// iam.ResourceAccessEntry / iam.ResourceAccessIndex / iam.ResourcePolicyGrant
// references working without changing every call site.
type (
	ResourceAccessEntry = access.ResourceAccessEntry
	ResourceAccessIndex = access.ResourceAccessIndex
	ResourcePolicyGrant = access.ResourcePolicyGrant
)

// NewResourceAccessIndex creates an empty index. Re-exported for
// callers that built indices through the iam package; the
// underlying constructor lives in core/access.
func NewResourceAccessIndex() *ResourceAccessIndex {
	return access.NewResourceAccessIndex()
}

// AddResourcePolicy parses an AWS resource-based policy document
// and indexes the principals it grants access to. accountID is the
// account that owns the resource, used to detect cross-account
// grants.
//
// Defined as a free function (not a method on ResourceAccessIndex)
// because the index type lives in core/access — Go forbids defining
// methods on types from another package.
func AddResourcePolicy(idx *ResourceAccessIndex, resourceARN, policyJSON, accountID string) error {
	if strings.TrimSpace(policyJSON) == "" {
		return nil // absent policy — skip, don't treat as empty
	}

	doc, err := ParsePolicyDocument(policyJSON)
	if err != nil {
		return err
	}

	for _, stmt := range doc.Allows() {
		principals := extractPrincipals(stmt)
		for _, principal := range principals {
			isPublic := principal == "*"
			isCrossAccount := !isPublic && !principalInAccount(principal, accountID)

			idx.AddEntry(resourceARN, access.ResourceAccessEntry{
				PrincipalARN:   principal,
				Actions:        stmt.Action,
				IsCrossAccount: isCrossAccount,
				IsPublic:       isPublic,
				GrantSource:    resourceARN,
			})
		}
	}
	return nil
}

// extractPrincipals extracts principal ARNs from a statement.
// In resource-based policies, Principal is usually specified in the
// statement but our simplified model stores it via the policy document's
// raw structure. For this iteration, principals are passed via the
// Resource field as a proxy — the extractor normalizes Principal into
// the actions/resource representation.
//
// For the simplified model: if any action has Resource: * and the
// statement has no conditions, treat it as accessible.
func extractPrincipals(stmt Statement) []string {
	// In our simplified model, the extractor pre-computes the accessible
	// principals and stores them in the Resource field of resource policy
	// allow statements. This is a practical approximation — full Principal
	// parsing requires handling AWS, Service, and Federated principal types.
	//
	// For now, we treat each Resource entry as a principal identifier
	// if it looks like an ARN or is "*".
	var principals []string
	for _, r := range stmt.Resource {
		if r == "*" || strings.HasPrefix(r, "arn:aws:iam:") ||
			strings.HasPrefix(r, "arn:aws:sts:") {
			principals = append(principals, r)
		}
	}
	// If no explicit principals found, check if actions suggest broad access.
	if len(principals) == 0 {
		if slices.Contains(stmt.Action, "*") {
			principals = append(principals, "*")
		}
	}
	return principals
}

// principalInAccount checks if a principal ARN belongs to the given account.
func principalInAccount(principalARN, accountID string) bool {
	if accountID == "" {
		return true // can't determine, assume same account
	}
	parsed := ExtractAccountID(principalARN)
	if parsed == "" {
		return true // can't parse, assume same account
	}
	return parsed == accountID
}
