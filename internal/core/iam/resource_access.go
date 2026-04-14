package iam

import (
	"slices"
	"strings"
)

// ResourceAccessEntry represents a principal's access to a resource
// granted via a resource-based policy.
type ResourceAccessEntry struct {
	PrincipalARN   string
	Actions        []string
	IsCrossAccount bool
	IsPublic       bool
	GrantSource    string // resource ARN that granted access
}

// ResourceAccessIndex maps resource ARNs to the set of principals with
// access via resource-based policies. Built once per snapshot evaluation.
type ResourceAccessIndex struct {
	entries map[string][]ResourceAccessEntry
}

// NewResourceAccessIndex creates an empty index.
func NewResourceAccessIndex() *ResourceAccessIndex {
	return &ResourceAccessIndex{
		entries: make(map[string][]ResourceAccessEntry),
	}
}

// EntriesFor returns all access entries for a resource ARN.
func (idx *ResourceAccessIndex) EntriesFor(resourceARN string) []ResourceAccessEntry {
	return idx.entries[resourceARN]
}

// HasNonDesignatedPHIAccess checks if a PHI resource has any accessor
// that is not in the designated principal set.
func (idx *ResourceAccessIndex) HasNonDesignatedPHIAccess(
	resourceARN string,
	designatedPrincipals map[string]bool,
) bool {
	for _, entry := range idx.entries[resourceARN] {
		if entry.IsPublic {
			return true // public access is never designated
		}
		if !designatedPrincipals[entry.PrincipalARN] {
			return true
		}
	}
	return false
}

// ResourcePolicyGrant is a resolved grant from a resource-based policy,
// included in the extended ResolvedPermissions output.
type ResourcePolicyGrant struct {
	ResourceARN    string
	Actions        []string
	IsCrossAccount bool
	IsPublic       bool
}

// AddResourcePolicy parses a resource-based policy document and indexes
// the principals it grants access to. accountID is the account that owns
// the resource, used to detect cross-account grants.
func (idx *ResourceAccessIndex) AddResourcePolicy(
	resourceARN string,
	policyJSON string,
	accountID string,
) error {
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

			idx.entries[resourceARN] = append(idx.entries[resourceARN],
				ResourceAccessEntry{
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
	// ARN format: arn:aws:iam::<account_id>:...
	parts := strings.Split(principalARN, ":")
	if len(parts) >= 5 {
		return parts[4] == accountID
	}
	return true // can't parse, assume same account
}
