package policy

import (
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// PrincipalScope determines the exposure level of the statement.
//
// Reads the parse-time-normalized Principal directly. The earlier
// shape decoded the raw Principal bytes on every access — see the
// Statement doc comment for why front-loading the decode is the
// SIR-export prerequisite.
func (s Statement) PrincipalScope() kernel.PrincipalScope {
	return s.Principal.Scope()
}

// ConditionAnalysis extracts scoping information from the Condition block.
//
// Reads the typed NormalizedCondition directly. The earlier shape
// re-decoded `s.Condition` on every call.
func (s Statement) ConditionAnalysis() ConditionAnalysis {
	return analyzeCondition(s.Condition)
}

// GrantsAccess reports whether this statement contributes to the reachable
// attack surface (i.e., it is an Allow, not a Deny or empty effect).
func (s Statement) GrantsAccess() bool {
	return s.Effect.IsAllow()
}

// IsPubliclyExposed reports whether this is an Allow statement with a public principal.
func (s Statement) IsPubliclyExposed() bool {
	return s.Effect.IsAllow() && s.PrincipalScope().IsPublic()
}

// HasWildcardActionsOnWildcardResources reports whether the statement
// grants all actions on all resources.
func (s Statement) HasWildcardActionsOnWildcardResources() bool {
	_, hasFullWildcardAction := s.ResolveActions()
	if !hasFullWildcardAction {
		return false
	}
	return hasWildcardResource([]string(s.Resource))
}

// EnforcesHTTPS reports whether this is a Deny statement requiring HTTPS.
//
// Operates on the typed Condition: looks up Bool/aws:SecureTransport
// directly through the map view. The earlier shape re-decoded the
// raw Condition bytes on every call.
func (s Statement) EnforcesHTTPS() bool {
	if !s.Effect.IsDeny() || !s.PrincipalScope().IsPublic() {
		return false
	}
	return hasSecureTransportFalse(s.Condition)
}

// PrincipalARNs extracts ARN strings from the Principal field.
//
// Returns only concrete ARNs — wildcards and empty strings are
// dropped. Uses the typed Principal directly via ConcreteAWSARNs;
// the earlier extractPrincipalARNs free function decoded raw JSON
// and ran the same filter.
func (s Statement) PrincipalARNs() []string {
	return s.Principal.ConcreteAWSARNs()
}

// HasWriteActions reports whether any action in the statement is a write action.
func (s Statement) HasWriteActions() bool {
	return slices.ContainsFunc([]string(s.Action), isWriteAction)
}
