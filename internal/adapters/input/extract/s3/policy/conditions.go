package policy

import "strings"

// NetworkKey represents the types of network-scoping keys we track.
type NetworkKey string

const (
	NetKeyIP   NetworkKey = "aws:sourceip"
	NetKeyVPCE NetworkKey = "aws:sourcevpce"
	NetKeyVPC  NetworkKey = "aws:sourcevpc"
	NetKeyOrg  NetworkKey = "aws:principalorgid"
)

// Map of keys to their respective flag setters.
var networkKeyRegistry = map[string]func(*ConditionAnalysis){
	string(NetKeyIP):   func(ca *ConditionAnalysis) { ca.HasIPCondition = true },
	string(NetKeyVPCE): func(ca *ConditionAnalysis) { ca.HasVPCCondition = true },
	string(NetKeyVPC):  func(ca *ConditionAnalysis) { ca.HasVPCCondition = true },
	string(NetKeyOrg):  func(ca *ConditionAnalysis) { ca.HasOrgCondition = true },
}

// analyzeCondition reduces the AWS Condition map into a network-scope analysis.
func analyzeCondition(raw any) ConditionAnalysis {
	analysis := ConditionAnalysis{}
	conds, ok := raw.(map[string]any)
	if !ok || len(conds) == 0 {
		return analysis
	}

	for operator, keys := range conds {
		op := normalizeOperator(operator)

		keyMap, ok := keys.(map[string]any)
		if !ok {
			continue
		}

		for key, values := range keyMap {
			k := strings.ToLower(key)

			// 1) Check whether the key is network scoping.
			setFlag, isNetworkKey := networkKeyRegistry[k]
			if !isNetworkKey {
				continue
			}

			// 2) Check whether operator+values create an effective constraint.
			valSlice := NormalizeStringOrSlice(values)
			if isEffectiveConstraint(op, valSlice) {
				setFlag(&analysis)
			}
		}
	}
	return analysis
}

// isEffectiveConstraint determines whether the condition is a real boundary.
func isEffectiveConstraint(op string, values []string) bool {
	if len(values) == 0 {
		return false
	}

	switch {
	case strings.Contains(op, "ipaddress"):
		// Any IPAddress/NotIpAddress with values is a scope boundary.
		return true

	case strings.Contains(op, "string") || strings.Contains(op, "arn"):
		// Ignore wildcard no-op patterns.
		for _, v := range values {
			if v != "*" {
				return true
			}
		}
	}

	return false
}

func normalizeOperator(op string) string {
	clean := strings.ToLower(op)
	clean = strings.TrimPrefix(clean, conditionPrefixForAnyValue)
	clean = strings.TrimPrefix(clean, conditionPrefixForAllValue)
	return strings.TrimSuffix(clean, conditionSuffixIfExists)
}
