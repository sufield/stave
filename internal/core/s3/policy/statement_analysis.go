package policy

import (
	"encoding/json"
	"slices"
	"strings"

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
func (s Statement) decodeRaw(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	_ = json.Unmarshal(raw, &v)
	return v
}

// hasSecureTransportCondition checks if Condition contains
// Bool.aws:SecureTransport = false.
func hasSecureTransportCondition(condition json.RawMessage) bool {
	if len(condition) == 0 {
		return false
	}

	var cond map[string]map[string]any
	if err := json.Unmarshal(condition, &cond); err != nil {
		return false
	}

	boolCond, ok := cond[condBool]
	if !ok {
		return false
	}

	raw, ok := boolCond[condSecureTransport]
	if !ok {
		return false
	}

	switch v := raw.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(v), condValueFalse)
	case bool:
		return !v
	default:
		return false
	}
}
