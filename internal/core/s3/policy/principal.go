package policy

import (
	"encoding/json"
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

		maxScope = upgradeScope(maxScope, scope)
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
			maxScope = upgradeScope(maxScope, kernel.ScopeAuthenticated)
		case isAccountIDOnly(p):
			maxScope = upgradeScope(maxScope, kernel.ScopeAccount)
		}
	}
	return maxScope
}

// upgradeScope returns the more permissive of two scopes.
func upgradeScope(current, candidate kernel.PrincipalScope) kernel.PrincipalScope {
	if scopePrecedence(candidate) > scopePrecedence(current) {
		return candidate
	}
	return current
}

// scopePrecedence maps scopes to integers for comparison.
// Higher values indicate greater exposure risk.
func scopePrecedence(s kernel.PrincipalScope) int {
	switch s {
	case kernel.ScopePublic:
		return 3
	case kernel.ScopeAuthenticated:
		return 2
	case kernel.ScopeCrossAccount, kernel.ScopeAccount:
		return 1
	default:
		return 0
	}
}

// classifyPolicyPrincipalScope is the internal entry point used by Statement.PrincipalScope().
func classifyPolicyPrincipalScope(p any) kernel.PrincipalScope {
	return NewPrincipal(p).Scope()
}
