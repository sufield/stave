package policy

import (
	"encoding/json"
	"slices"

	"github.com/sufield/stave/internal/core/kernel"
)

// PrincipalScope determines the exposure level of the statement.
func (s Statement) PrincipalScope() kernel.PrincipalScope {
	return classifyPolicyPrincipalScope(s.decodeRaw(s.Principal))
}

// ConditionAnalysis extracts scoping information from the Condition block.
func (s Statement) ConditionAnalysis() ConditionAnalysis {
	return analyzeCondition(s.decodeRaw(s.Condition))
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
func (s Statement) EnforcesHTTPS() bool {
	if !s.Effect.IsDeny() || !s.PrincipalScope().IsPublic() {
		return false
	}
	return hasSecureTransportCondition(s.Condition)
}

// PrincipalARNs extracts ARN strings from the Principal field.
func (s Statement) PrincipalARNs() []string {
	return extractPrincipalARNs(s.decodeRaw(s.Principal))
}

// HasWriteActions reports whether any action in the statement is a write action.
func (s Statement) HasWriteActions() bool {
	return slices.ContainsFunc([]string(s.Action), isWriteAction)
}

// decodeRaw unmarshals a json.RawMessage into any, used for Principal
// and Condition fields that have varying JSON shapes.
//
// Returns nil on unmarshal failure rather than an error: AGENTS.md
// requires core/ to be side-effect-free (no logging) and threading an
// error through every caller (PrincipalScope, ConditionAnalysis,
// PrincipalARNs, and their callers up the chain) is heavier than the
// contract warrants. The bytes here come from a `json.RawMessage`
// field already validated by the outer Statement unmarshal in
// adapters/, so a parse failure here would indicate corrupted
// post-validation input — extremely unlikely. Callers all handle
// `nil` cleanly: PrincipalScope returns Public-or-Restricted based
// on the type assertion, ConditionAnalysis returns the zero analysis,
// PrincipalARNs returns an empty slice.
func (s Statement) decodeRaw(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	_ = json.Unmarshal(raw, &v) //nolint:errcheck // see doc comment: nil-on-failure is the documented contract
	return v
}
