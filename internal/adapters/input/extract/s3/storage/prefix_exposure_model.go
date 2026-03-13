package storage

import (
	"encoding/json"
	"strconv"
	"strings"

	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3policy "github.com/sufield/stave/internal/adapters/input/extract/s3/policy"
	"github.com/sufield/stave/internal/domain/kernel"
)

type prefixExposureModelInput struct {
	PolicyJSON     string
	ACLAnalysis    s3acl.Analysis
	HasACLAnalysis bool
	PolicyBlocked  bool
	ACLBlocked     bool
}

func buildPrefixExposureModel(in prefixExposureModelInput) S3PrefixExposure {
	scopes, sourceByScope := extractPublicReadScopesFromPolicy(in.PolicyJSON)
	hasPolicyEvidence := strings.TrimSpace(in.PolicyJSON) != ""
	aclPublicReadAll := in.HasACLAnalysis && in.ACLAnalysis.AllowsPublicRead

	out := S3PrefixExposure{
		HasIdentityEvidence:   hasPolicyEvidence,
		HasResourceEvidence:   in.HasACLAnalysis,
		IdentityReadScopes:    scopes,
		IdentitySourceByScope: sourceByScope,
		IdentityReadBlocked:   in.PolicyBlocked,
		ResourceReadAll:       aclPublicReadAll,
		ResourceReadBlocked:   in.ACLBlocked,
	}
	return out
}

// extractPublicReadScopesFromPolicy normalizes policy public-read grants to generic scopes.
// Scope "*" means all prefixes; otherwise values are normalized to "prefix/".
func extractPublicReadScopesFromPolicy(policyJSON string) ([]kernel.ObjectPrefix, map[kernel.ObjectPrefix]string) {
	var scopes []kernel.ObjectPrefix
	sourceByScope := make(map[kernel.ObjectPrefix]string)
	if strings.TrimSpace(policyJSON) == "" {
		return scopes, sourceByScope
	}

	var policy s3policy.BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return scopes, sourceByScope
	}

	seen := make(map[kernel.ObjectPrefix]bool)
	for i, stmt := range policy.Statement {
		if !stmt.Effect.IsAllow() {
			continue
		}
		if !s3policy.IsPublicPrincipal(stmt.Principal) {
			continue
		}

		actions := []string(stmt.Action)
		if !hasPublicReadAction(actions) {
			continue
		}

		resources := []string(stmt.Resource)
		scope := scopeFromResources(resources)
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		scopes = append(scopes, scope)

		sid := strings.TrimSpace(stmt.Sid)
		if sid == "" {
			sid = "stmt-" + strconv.Itoa(i)
		}
		sourceByScope[scope] = sid
	}

	return scopes, sourceByScope
}

func hasPublicReadAction(actions []string) bool {
	for _, action := range actions {
		a := strings.ToLower(strings.TrimSpace(action))
		if a == "*" || a == "s3:*" || a == "s3:getobject" {
			return true
		}
	}
	return false
}

func scopeFromResources(resources []string) kernel.ObjectPrefix {
	for _, res := range resources {
		scope := scopeFromResourcePattern(res)
		if scope != "" {
			return scope
		}
	}
	return ""
}

func scopeFromResourcePattern(resource string) kernel.ObjectPrefix {
	parts := strings.SplitN(strings.TrimSpace(resource), ":::", 2)
	if len(parts) != 2 {
		return ""
	}
	after := parts[1]
	_, path, hasPath := strings.Cut(after, "/")
	if !hasPath {
		return ""
	}
	if path == "*" {
		return kernel.WildcardPrefix
	}
	if before, ok := strings.CutSuffix(path, "/*"); ok {
		scope := before
		if scope == "" {
			return kernel.WildcardPrefix
		}
		if !strings.HasSuffix(scope, "/") {
			scope += "/"
		}
		return kernel.ObjectPrefix(scope)
	}
	return ""
}
