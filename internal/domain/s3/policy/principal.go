package policy

import (
	"encoding/json"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

type principalHandler func(any) kernel.PrincipalScope

// Principal wraps raw IAM principal data and encapsulates classification logic.
type Principal struct {
	raw any
}

func NewPrincipal(p any) Principal {
	if raw, ok := p.(json.RawMessage); ok {
		var v any
		if err := json.Unmarshal(raw, &v); err == nil {
			return Principal{raw: v}
		}
	}
	return Principal{raw: p}
}

var principalHandlers = map[string]principalHandler{
	"aws":           handleAWSPrincipal,
	"service":       func(any) kernel.PrincipalScope { return kernel.ScopeAccount },
	"federated":     func(any) kernel.PrincipalScope { return kernel.ScopePublic },
	"canonicaluser": func(any) kernel.PrincipalScope { return kernel.ScopeAccount },
	"*":             func(any) kernel.PrincipalScope { return kernel.ScopePublic },
}

// Scope determines whether the principal is public, authenticated, or private.
func (p Principal) Scope() kernel.PrincipalScope {
	switch raw := p.raw.(type) {
	case string:
		if raw == policyWildcard {
			return kernel.ScopePublic
		}
		return kernel.ScopeAccount
	case map[string]any:
		return p.analyzeMap(raw)
	default:
		return kernel.ScopeAccount
	}
}

func (p Principal) analyzeMap(m map[string]any) kernel.PrincipalScope {
	maxScope := kernel.ScopeAccount
	for key, value := range m {
		handler, exists := principalHandlers[strings.ToLower(key)]
		if !exists {
			continue
		}

		scope := handler(value)
		if principalScopePrecedence(scope) > principalScopePrecedence(maxScope) {
			maxScope = scope
		}
	}
	return maxScope
}

func classifyPolicyPrincipalScope(p any) kernel.PrincipalScope {
	return NewPrincipal(p).Scope()
}

func handleAWSPrincipal(val any) kernel.PrincipalScope {
	values := NormalizeStringOrSlice(val)
	maxScope := kernel.ScopeAccount

	for _, v := range values {
		switch {
		case v == policyWildcard:
			return kernel.ScopePublic
		case isAccountIDOnly(v):
			// Account ID principals are private to a single account.
			maxScope = morePermissivePrincipalScope(maxScope, kernel.ScopeAccount)
		case strings.Contains(v, ":iam::*:root"):
			maxScope = morePermissivePrincipalScope(maxScope, kernel.ScopeAuthenticated)
		}
	}
	return maxScope
}

func morePermissivePrincipalScope(current, candidate kernel.PrincipalScope) kernel.PrincipalScope {
	if principalScopePrecedence(candidate) > principalScopePrecedence(current) {
		return candidate
	}
	return current
}

func principalScopePrecedence(scope kernel.PrincipalScope) int {
	switch scope {
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

// isAuthenticatedPrincipal checks if a principal grants access to any authenticated AWS user.
func isAuthenticatedPrincipal(principal any) bool {
	return classifyPolicyPrincipalScope(principal) == kernel.ScopeAuthenticated
}

// IsPublicPrincipal checks if a principal grants public access.
func IsPublicPrincipal(principal any) bool {
	return classifyPolicyPrincipalScope(principal).IsPublic()
}
