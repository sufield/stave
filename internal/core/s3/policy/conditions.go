package policy

import "strings"

// Condition keys for network scoping.
const (
	keySourceIP     = "aws:sourceip"
	keySourceVPCE   = "aws:sourcevpce"
	keySourceVPC    = "aws:sourcevpc"
	keyPrincipalOrg = "aws:principalorgid"
)

// analyzeCondition reduces an AWS Condition map into a network-scope analysis.
// AWS Condition structure: map[Operator]map[Key]Value(s).
func analyzeCondition(raw any) ConditionAnalysis {
	analysis := ConditionAnalysis{}

	operators, ok := raw.(map[string]any)
	if !ok || len(operators) == 0 {
		return analysis
	}

	for opRaw, keysRaw := range operators {
		op := normalizeOperator(opRaw)

		keys, ok := keysRaw.(map[string]any)
		if !ok {
			continue
		}

		for keyRaw, valuesRaw := range keys {
			key := strings.ToLower(keyRaw)

			values := NormalizeStringOrSlice(valuesRaw)
			if !isEffectiveConstraint(op, values) {
				continue
			}

			analysis.ConditionKeys = append(analysis.ConditionKeys, key)
			switch key {
			case keySourceIP:
				analysis.HasIPCondition = true
			case keySourceVPCE, keySourceVPC:
				analysis.HasVPCCondition = true
			case keyPrincipalOrg:
				analysis.HasOrgCondition = true
			}
		}
	}
	return analysis
}

// isEffectiveConstraint determines whether a condition actually restricts
// access. A wildcard value (e.g., StringLike: {"aws:SourceVpce": "*"})
// is a no-op in AWS and should not be treated as a real boundary.
func isEffectiveConstraint(op string, values []string) bool {
	if len(values) == 0 {
		return false
	}

	// IPAddress and NotIpAddress are almost always effective boundaries.
	if strings.Contains(op, "ipaddress") {
		return true
	}

	// String and ARN operators require at least one non-wildcard value.
	if strings.Contains(op, "string") || strings.Contains(op, "arn") {
		for _, v := range values {
			if v != wildcard {
				return true
			}
		}
		return false
	}

	// Bool operators (like aws:SecureTransport) are effective if present.
	if strings.Contains(op, "bool") {
		return true
	}

	return false
}

// normalizeOperator strips AWS-specific modifiers from the operator name.
// e.g., "ForAnyValue:StringEqualsIfExists" → "stringequals".
func normalizeOperator(op string) string {
	clean := strings.ToLower(op)
	clean = strings.TrimPrefix(clean, condPrefixForAnyValue)
	clean = strings.TrimPrefix(clean, condPrefixForAllValues)
	return strings.TrimSuffix(clean, condSuffixIfExists)
}
