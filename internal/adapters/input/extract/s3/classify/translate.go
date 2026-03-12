package classify

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/exposure"
)

// S3 action-to-permission mapping.
var actionToPerm = map[string]exposure.Permission{
	"*":                     exposure.PermAll,
	"s3:*":                  exposure.PermAll,
	"s3:getobject":          exposure.PermRead,
	"s3:putobject":          exposure.PermWrite,
	"s3:listbucket":         exposure.PermList,
	"s3:listbucketversions": exposure.PermList,
	"s3:getbucketacl":       exposure.PermMetadataRead,
	"s3:getobjectacl":       exposure.PermMetadataRead,
	"s3:putbucketacl":       exposure.PermMetadataWrite,
	"s3:putobjectacl":       exposure.PermMetadataWrite,
	"s3:deleteobject":       exposure.PermDelete,
	"s3:deletebucket":       exposure.PermDelete,
}

// Normalize converts an S3-specific bucket input into a vendor-neutral NormalizedResourceInput.
func Normalize(input S3BucketInput) exposure.NormalizedResourceInput {
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
func NormalizeAll(inputs []S3BucketInput) []exposure.NormalizedResourceInput {
	normalized := make([]exposure.NormalizedResourceInput, len(inputs))
	for i, b := range inputs {
		normalized[i] = Normalize(b)
	}
	return normalized
}

// ClassifyS3Exposure normalizes S3-specific bucket inputs and classifies exposure.
func ClassifyS3Exposure(buckets []S3BucketInput) []exposure.ExposureClassification {
	return exposure.ClassifyExposure(NormalizeAll(buckets))
}

// --- Policy Inspection ---

func inspectPolicy(result *exposure.NormalizedResourceInput, policy PolicyConfig) {
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

func inspectACL(result *exposure.NormalizedResourceInput, acl ACLConfig) {
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
		if p, ok := actionToPerm[strings.ToLower(action)]; ok {
			mask |= p
		}
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
	if strings.Contains(strings.ToLower(p), principalTokenAuthenticatedUsers) {
		return false, true
	}
	return false, false
}

// --- ACL Grant Helpers ---

func grantIsAllUsers(g ACLGrant) bool {
	return strings.Contains(strings.ToLower(g.Grantee), principalTokenAllUsers)
}

func grantIsPublic(g ACLGrant) bool {
	grantee := strings.ToLower(g.Grantee)
	return strings.Contains(grantee, principalTokenAllUsers) ||
		strings.Contains(grantee, principalTokenAuthenticatedUsers)
}

func grantPermissions(g ACLGrant) exposure.Permission {
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
