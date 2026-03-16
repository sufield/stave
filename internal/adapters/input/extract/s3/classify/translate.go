package classify

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/exposure"
)

// mapActionToPermission maps an S3 action string to a domain permission bitmask.
// Uses prefix/contains matching to handle action variants (e.g., s3:GetObjectVersion).
func mapActionToPermission(action string) exposure.Permission {
	a := strings.ToLower(strings.TrimSpace(action))
	switch {
	case a == "*" || a == "s3:*":
		return exposure.PermAll
	case strings.Contains(a, "getobject"):
		return exposure.PermRead
	case strings.Contains(a, "putobject"):
		return exposure.PermWrite
	case strings.Contains(a, "listbucket"):
		return exposure.PermList
	case strings.Contains(a, "deleteobject") || strings.Contains(a, "deletebucket"):
		return exposure.PermDelete
	case strings.Contains(a, "acl"):
		if strings.Contains(a, "get") {
			return exposure.PermMetadataRead
		}
		return exposure.PermMetadataWrite
	default:
		return 0
	}
}

// Normalize converts an S3-specific bucket input into a vendor-neutral NormalizedResourceInput.
func Normalize(input Bucket) exposure.NormalizedResourceInput {
	result := exposure.NormalizedResourceInput{
		Name:                input.Name,
		Exists:              input.Exists,
		ExternalReference:   input.ExternalReference,
		WebsiteEnabled:      input.Website.Enabled,
		IsAuthenticatedOnly: true,
		Evidence:            exposure.NewEvidenceTracker(),
	}

	inspectPolicy(&result, input.Policy)
	inspectACL(&result, input.ACL)

	return result
}

// NormalizeAll converts a slice of S3 bucket inputs into normalized inputs.
func NormalizeAll(inputs []Bucket) []exposure.NormalizedResourceInput {
	normalized := make([]exposure.NormalizedResourceInput, len(inputs))
	for i, b := range inputs {
		normalized[i] = Normalize(b)
	}
	return normalized
}

// ClassifyS3Exposure normalizes S3-specific bucket inputs and classifies exposure.
func ClassifyS3Exposure(buckets []Bucket) []exposure.ExposureClassification {
	return exposure.ClassifyExposure(NormalizeAll(buckets))
}

// --- Policy Inspection ---

func inspectPolicy(result *exposure.NormalizedResourceInput, policy Policy) {
	for i, stmt := range policy.Statements {
		if !strings.EqualFold(stmt.Effect, "allow") {
			continue
		}

		isGlobal, isAuthenticated := classifyPrincipal(stmt.Principal)
		if !isGlobal && !isAuthenticated {
			continue
		}
		if isGlobal {
			result.IsAuthenticatedOnly = false
		}

		perms := analyzeActions(stmt.Actions)
		recordPerms(result, perms, policyEvidence(i), true, exposure.EvIdentityRead, exposure.EvIdentityWrite)
	}
}

// --- ACL Inspection ---

func inspectACL(result *exposure.NormalizedResourceInput, acl ACL) {
	for i, grant := range acl.Grants {
		if !grantIsPublic(grant) {
			continue
		}
		if grantIsAllUsers(grant) {
			result.IsAuthenticatedOnly = false
		}
		recordPerms(result, grantPermissions(grant), aclEvidence(i), false, exposure.EvResourceRead, exposure.EvResourceWrite)
	}
}

// --- Permission Recording ---

func recordPerms(
	result *exposure.NormalizedResourceInput,
	perms exposure.Permission,
	path []string,
	isPolicy bool,
	readCat, writeCat exposure.EvidenceCategory,
) {
	// Handle write source tracking (first write source wins).
	if perms.Has(exposure.PermWrite) {
		if !result.IdentityPerms.Has(exposure.PermWrite) && !result.ResourcePerms.Has(exposure.PermWrite) {
			result.WriteSourceHasGet = perms.Has(exposure.PermRead)
			result.WriteSourceHasList = perms.Has(exposure.PermList)
		}
		result.Evidence.Record(writeCat, path)
	}

	// Select target permission set.
	target := &result.ResourcePerms
	if isPolicy {
		target = &result.IdentityPerms
	}

	// Table-driven bit dispatch.
	type mapping struct {
		bit exposure.Permission
		cat exposure.EvidenceCategory
	}
	for _, m := range []mapping{
		{exposure.PermRead, readCat},
		{exposure.PermWrite, writeCat},
		{exposure.PermList, exposure.EvDiscovery},
		{exposure.PermMetadataRead, exposure.EvResourceAdminRead},
		{exposure.PermMetadataWrite, exposure.EvResourceAdminRead},
		{exposure.PermDelete, exposure.EvDelete},
	} {
		if perms.Has(m.bit) {
			*target |= m.bit
			result.Evidence.Record(m.cat, path)
		}
	}
}

// --- Action Analysis ---

func analyzeActions(actions []string) exposure.Permission {
	var mask exposure.Permission
	for _, action := range actions {
		mask |= mapActionToPermission(action)
		if mask == exposure.PermAll {
			break
		}
	}
	return mask
}

// --- Principal Classification ---

const (
	principalWildcard                = "*"
	principalTokenAllUsers           = "allusers"
	principalTokenAuthenticatedUsers = "authenticatedusers"
)

func classifyPrincipal(principal string) (isGlobal, isAuthenticated bool) {
	p := strings.TrimSpace(principal)
	if p == principalWildcard {
		return true, false
	}
	if matchesPrincipalToken(p, principalTokenAuthenticatedUsers) {
		return false, true
	}
	return false, false
}

// --- ACL Grant Helpers ---

func grantIsAllUsers(g Grant) bool {
	return matchesPrincipalToken(g.Grantee, principalTokenAllUsers)
}

func grantIsPublic(g Grant) bool {
	return matchesPrincipalToken(g.Grantee, principalTokenAllUsers) ||
		matchesPrincipalToken(g.Grantee, principalTokenAuthenticatedUsers)
}

// matchesPrincipalToken checks if a principal string matches a token.
// Handles bare tokens ("allusers"), URI paths (".../AllUsers"),
// and AWS prefixed forms ("AWS:AuthenticatedUsers").
func matchesPrincipalToken(principal, token string) bool {
	v := strings.ToLower(strings.TrimSpace(principal))
	return v == token ||
		strings.HasSuffix(v, "/"+token) ||
		strings.HasSuffix(v, ":"+token)
}

func grantPermissions(g Grant) exposure.Permission {
	perm := strings.ToUpper(strings.TrimSpace(g.Permission))
	scope := strings.ToLower(strings.TrimSpace(g.Scope))

	if perm == "FULL_CONTROL" {
		return exposure.PermAll
	}

	switch perm {
	case "READ":
		if scope == "bucket" {
			return exposure.PermList
		}
		return exposure.PermRead
	case "WRITE":
		return exposure.PermWrite
	case "READ_ACP":
		return exposure.PermMetadataRead
	case "WRITE_ACP":
		return exposure.PermMetadataWrite
	default:
		return 0
	}
}

// --- Evidence Path Helpers ---

func policyEvidence(idx int) []string {
	p := fmt.Sprintf("bucket.policy.statements[%d]", idx)
	return []string{p + ".effect", p + ".principal", p + ".actions"}
}

func aclEvidence(idx int) []string {
	p := fmt.Sprintf("bucket.acl.grants[%d]", idx)
	return []string{p + ".grantee", p + ".permission", p + ".scope"}
}
