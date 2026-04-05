package policy

import "strings"

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
