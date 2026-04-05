package policy

import (
	"encoding/json"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// --- Condition operator classification ---

// condOperator is a normalized IAM condition operator (lowercase, modifiers stripped).
type condOperator string

// parseOperator normalizes an AWS condition operator by stripping list
// modifiers (ForAnyValue:, ForAllValues:) and null-safety (IfExists).
func parseOperator(raw string) condOperator {
	clean := strings.ToLower(raw)
	clean = strings.TrimPrefix(clean, condPrefixForAnyValue)
	clean = strings.TrimPrefix(clean, condPrefixForAllValues)
	return condOperator(strings.TrimSuffix(clean, condSuffixIfExists))
}

func (op condOperator) isIPAddress() bool { return strings.Contains(string(op), "ipaddress") }
func (op condOperator) isBoolean() bool   { return strings.Contains(string(op), "bool") }
func (op condOperator) isStringOrARN() bool {
	s := string(op)
	return strings.Contains(s, "string") || strings.Contains(s, "arn")
}

// --- Condition key classification ---

// condKey is a normalized IAM condition key (lowercase).
type condKey string

const (
	keySourceIP     condKey = "aws:sourceip"
	keySourceVPCE   condKey = "aws:sourcevpce"
	keySourceVPC    condKey = "aws:sourcevpc"
	keyPrincipalOrg condKey = "aws:principalorgid"
)

func (k condKey) isNetworkBoundary() bool {
	return k == keySourceIP || k == keySourceVPCE || k == keySourceVPC
}

func (k condKey) isOrgBoundary() bool {
	return k == keyPrincipalOrg
}

// --- Condition analysis ---

// analyzeCondition reduces an AWS Condition map into a network-scope analysis.
// AWS Condition structure: map[Operator]map[Key]Value(s).
func analyzeCondition(raw any) ConditionAnalysis {
	analysis := ConditionAnalysis{}

	operators, ok := raw.(map[string]any)
	if !ok || len(operators) == 0 {
		return analysis
	}

	for opRaw, keysRaw := range operators {
		op := parseOperator(opRaw)

		keys, ok := keysRaw.(map[string]any)
		if !ok {
			continue
		}

		for keyRaw, valuesRaw := range keys {
			key := condKey(strings.ToLower(keyRaw))
			values := NormalizeStringOrSlice(valuesRaw)

			if !op.isEffective(values) {
				continue
			}

			analysis.ConditionKeys = append(analysis.ConditionKeys, ConditionKey(string(key)))
			switch {
			case key == keySourceIP:
				analysis.HasIPCondition = true
			case key.isNetworkBoundary():
				analysis.HasVPCCondition = true
			case key.isOrgBoundary():
				analysis.HasOrgCondition = true
			}
		}
	}
	return analysis
}

// isEffective determines whether this operator with these values actually
// restricts access. Wildcard values are no-ops in AWS.
func (op condOperator) isEffective(values []string) bool {
	if len(values) == 0 {
		return false
	}
	if op.isIPAddress() || op.isBoolean() {
		return true
	}
	if op.isStringOrARN() {
		for _, v := range values {
			if v != wildcard {
				return true
			}
		}
		return false
	}
	return false
}

// hasSecureTransportCondition checks if a Condition JSON block contains
// Bool: {aws:SecureTransport: false} — the standard HTTPS enforcement pattern.
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
		return strings.EqualFold(strings.TrimSpace(v), "false")
	case bool:
		return !v
	default:
		return false
	}
}

// ResolveNetworkScope maps condition flags to a high-level network boundary.
// Precedence: vpc > ip > org > public.
func (ca ConditionAnalysis) ResolveNetworkScope() kernel.NetworkScope {
	switch {
	case ca.HasVPCCondition:
		return kernel.NetworkScopeVPCRestricted
	case ca.HasIPCondition:
		return kernel.NetworkScopeIPRestricted
	case ca.HasOrgCondition:
		return kernel.NetworkScopeOrgRestricted
	default:
		return kernel.NetworkScopePublic
	}
}

// --- Condition types ---

// ConditionKey is a typed string identifying an AWS policy condition key.
type ConditionKey string

// Well-known AWS condition keys.
const (
	CondKeySourceIP       ConditionKey = "aws:SourceIp"
	CondKeySourceVPC      ConditionKey = "aws:sourceVpc"
	CondKeyPrincipalOrgID ConditionKey = "aws:PrincipalOrgID"
)

// ConditionAnalysis contains the result of an AWS policy condition inspection.
type ConditionAnalysis struct {
	HasIPCondition  bool
	HasVPCCondition bool
	HasOrgCondition bool
	ConditionKeys   []ConditionKey
}

// IsNetworkScoped reports whether any network-scoping condition is present.
func (ca ConditionAnalysis) IsNetworkScoped() bool {
	return ca.HasIPCondition || ca.HasVPCCondition || ca.HasOrgCondition
}
