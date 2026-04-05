package policy

import "github.com/sufield/stave/internal/core/kernel"

// resolveConditionScope maps a ConditionAnalysis to a kernel.NetworkScope.
// Precedence: vpc > ip > org > public.
func resolveConditionScope(ca ConditionAnalysis) kernel.NetworkScope {
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
