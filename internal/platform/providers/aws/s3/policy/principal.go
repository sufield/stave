package policy

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// Internal constants for AWS principal type keys.
const (
	keyAWS           = "aws"
	keyService       = "service"
	keyFederated     = "federated"
	keyCanonicalUser = "canonicaluser"
)

// Principal wraps raw IAM principal data and encapsulates classification logic.
type Principal struct {
	data any
}

// NewPrincipal handles the polymorphism of the Principal JSON field.
// If p is a json.RawMessage, it is decoded first. If decoding fails,
// data is set to nil to prevent downstream type-assertion issues.
func NewPrincipal(p any) Principal {
	if raw, ok := p.(json.RawMessage); ok {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return Principal{data: nil}
		}
		return Principal{data: v}
	}
	return Principal{data: p}
}

// Scope determines whether the principal is public, authenticated, or account-scoped.
func (p Principal) Scope() kernel.PrincipalScope {
	if p.data == nil {
		return kernel.ScopeAccount
	}

	switch v := p.data.(type) {
	case string:
		if isWildcardPrincipal(v) {
			return kernel.ScopePublic
		}
		return kernel.ScopeAccount
	case map[string]any:
		return p.analyzeMap(v)
	default:
		return kernel.ScopeAccount
	}
}

// analyzeMap iterates principal type keys and returns the most permissive scope.
func (p Principal) analyzeMap(m map[string]any) kernel.PrincipalScope {
	maxScope := kernel.ScopeAccount

	for key, value := range m {
		var scope kernel.PrincipalScope

		switch strings.ToLower(key) {
		case keyAWS:
			scope = classifyAWSPrincipal(value)
		case keyFederated, wildcard:
			scope = kernel.ScopePublic
		case keyService, keyCanonicalUser:
			scope = kernel.ScopeAccount
		default:
			continue
		}

		maxScope = morePermissive(maxScope, scope)
	}
	return maxScope
}

// classifyAWSPrincipal isolates the AWS-specific ARN parsing logic.
func classifyAWSPrincipal(val any) kernel.PrincipalScope {
	principals := NormalizeStringOrSlice(val)
	maxScope := kernel.ScopeAccount

	for _, p := range principals {
		switch {
		case isWildcardPrincipal(p):
			return kernel.ScopePublic
		case strings.Contains(p, ":iam::*:root"):
			maxScope = morePermissive(maxScope, kernel.ScopeAuthenticated)
		case isAccountIDOnly(p):
			maxScope = morePermissive(maxScope, kernel.ScopeAccount)
		}
	}
	return maxScope
}

// morePermissive returns whichever scope has the wider blast radius.
func morePermissive(current, candidate kernel.PrincipalScope) kernel.PrincipalScope {
	if candidate.IsMorePermissiveThan(current) {
		return candidate
	}
	return current
}

// classifyPolicyPrincipalScope is the internal entry point used by Statement.PrincipalScope().
func classifyPolicyPrincipalScope(p any) kernel.PrincipalScope {
	return NewPrincipal(p).Scope()
}

// --- Principal extraction helpers ---

// reAccountID matches exactly 12 digits (AWS Account ID format).
var reAccountID = regexp.MustCompile(`^\d{12}$`)

// isAccountIDOnly reports whether the principal is a bare 12-digit account ID.
func isAccountIDOnly(principal string) bool {
	return reAccountID.MatchString(principal)
}

// extractPrincipalARNs extracts concrete AWS ARNs (excluding wildcards)
// from a decoded Principal field.
func extractPrincipalARNs(principal any) []string {
	var target any
	switch p := principal.(type) {
	case string:
		target = p
	case map[string]any:
		if awsEntry, ok := p[principalAWS]; ok {
			target = awsEntry
		}
	default:
		// Unrecognized principal type — target stays nil.
	}
	if target == nil {
		return nil
	}

	candidates := NormalizeStringOrSlice(target)
	filtered := slices.DeleteFunc(candidates, func(arn string) bool {
		return arn == "" || isWildcardPrincipal(arn)
	})
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}
