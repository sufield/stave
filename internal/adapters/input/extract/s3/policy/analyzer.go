package policy

import (
	"encoding/json"
	"regexp"

	"github.com/sufield/stave/internal/domain/kernel"
)

// accountARNPattern matches AWS account ARNs like arn:aws:iam::123456789012:root/role/user.
var accountARNPattern = regexp.MustCompile(`^arn:aws:iam::(\d{12}):`)

// Engine parses a policy once and exposes focused analyzers over the parsed model.
type Engine struct {
	policy BucketPolicy
}

func NewEngine(policyJSON string) (*Engine, error) {
	var policy BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return nil, err
	}
	return &Engine{policy: policy}, nil
}

// AnalyzePolicy parses and analyzes an S3 bucket policy JSON string.
func AnalyzePolicy(policyJSON string) Analysis {
	engine, ok := newEngine(policyJSON)
	if !ok {
		return Analysis{}
	}
	return engine.FullAnalysis()
}

func (e *Engine) FullAnalysis() Analysis {
	result := Analysis{}
	state := policyAnalysisState{}
	for i, stmt := range e.policy.Statement {
		state.processStatement(&result, stmt, i)
	}
	applyPermissionMasks(&result, state.publicPerms, state.authPerms)
	result.EffectiveNetworkScope = toKernelNetworkScope(state.weakestScope)
	return result
}

type policyAnalysisState struct {
	weakestScope networkScope
	publicPerms  policyActionMask
	authPerms    policyActionMask
}

func (s *policyAnalysisState) processStatement(result *Analysis, stmt Statement, index int) {
	if !stmt.IsAllow() {
		return
	}

	scope := stmt.PrincipalScope()
	if scope == kernel.ScopeAccount {
		return
	}

	condition := stmt.ConditionAnalysis()
	updateNetworkConditionFlags(result, condition)
	s.updateWeakestScope(conditionScope(condition))

	actionMask, _ := stmt.ResolveActions()
	if actionMask != 0 {
		result.PublicStatements = append(result.PublicStatements, stmt.ID(index))
	}
	s.updatePermissionMasks(stmt, scope, condition, actionMask)
	result.HasWildcardActions = result.HasWildcardActions || stmt.HasWildcardActionsOnWildcardResources()
}

func updateNetworkConditionFlags(result *Analysis, condition ConditionAnalysis) {
	if !condition.IsNetworkScoped() {
		return
	}
	result.HasNetworkCondition = true
	result.HasIPCondition = result.HasIPCondition || condition.HasIPCondition
	result.HasVPCCondition = result.HasVPCCondition || condition.HasVPCCondition
}

func (s *policyAnalysisState) updateWeakestScope(scope networkScope) {
	if s.weakestScope == "" || scope.weakerThan(s.weakestScope) {
		s.weakestScope = scope
	}
}

func (s *policyAnalysisState) updatePermissionMasks(
	stmt Statement,
	scope kernel.PrincipalScope,
	condition ConditionAnalysis,
	actionMask policyActionMask,
) {
	switch {
	case stmt.IsPubliclyExposed():
		if !condition.IsNetworkScoped() {
			s.publicPerms |= actionMask
		}
	case scope == kernel.ScopeAuthenticated:
		s.authPerms |= actionMask
	}
}

// AnalyzeTransportEncryption checks if a bucket policy enforces HTTPS via a Deny
// statement with condition aws:SecureTransport = "false".
func AnalyzeTransportEncryption(policyJSON string) TransportEncryptionAnalysis {
	engine, ok := newEngine(policyJSON)
	if !ok {
		return TransportEncryptionAnalysis{}
	}
	return engine.TransportEncryptionAnalysis()
}

func (e *Engine) TransportEncryptionAnalysis() TransportEncryptionAnalysis {
	for _, stmt := range e.policy.Statement {
		if stmt.EnforcesHTTPS() {
			return TransportEncryptionAnalysis{EnforcesHTTPS: true}
		}
	}
	return TransportEncryptionAnalysis{}
}

// AnalyzeCrossAccountAccess extracts external AWS account ARNs from a bucket policy.
func AnalyzeCrossAccountAccess(policyJSON string) CrossAccountAnalysis {
	engine, ok := newEngine(policyJSON)
	if !ok {
		return CrossAccountAnalysis{}
	}
	return engine.CrossAccountAnalysis()
}

func (e *Engine) CrossAccountAnalysis() CrossAccountAnalysis {
	result := CrossAccountAnalysis{}
	seen := make(map[string]bool)

	for _, stmt := range e.policy.Statement {
		if !stmt.IsAllow() {
			continue
		}

		principals := stmt.PrincipalARNs()
		if len(principals) == 0 {
			continue
		}

		for _, arn := range principals {
			accountID, ok := extractAccountID(arn)
			if !ok {
				continue
			}
			if !seen[accountID] {
				seen[accountID] = true
				result.ExternalAccountARNs = append(result.ExternalAccountARNs, arn)
				result.ExternalAccountIDs = append(result.ExternalAccountIDs, accountID)
			}
		}

		if stmt.HasWriteActions() {
			result.HasExternalWrite = true
		}
	}

	result.HasExternalAccess = len(result.ExternalAccountARNs) > 0
	return result
}

func extractAccountID(arn string) (string, bool) {
	matches := accountARNPattern.FindStringSubmatch(arn)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

func newEngine(policyJSON string) (*Engine, bool) {
	if policyJSON == "" {
		return nil, false
	}
	engine, err := NewEngine(policyJSON)
	if err != nil {
		// Invalid JSON, treat as no policy.
		return nil, false
	}
	return engine, true
}

func applyPermissionMasks(result *Analysis, publicPerms, authPerms policyActionMask) {
	result.AllowsPublicRead = publicPerms.has(policyActionRead)
	result.AllowsPublicList = publicPerms.has(policyActionList)
	result.AllowsPublicWrite = publicPerms.has(policyActionWrite)
	result.AllowsPublicDelete = publicPerms.has(policyActionDelete)
	result.AllowsPublicACLWrite = publicPerms.has(policyActionACLWrite)
	result.AllowsPublicACLRead = publicPerms.has(policyActionACLRead)

	result.AllowsAuthenticatedRead = authPerms.has(policyActionRead)
	result.AllowsAuthenticatedList = authPerms.has(policyActionList)
	result.AllowsAuthenticatedWrite = authPerms.has(policyActionWrite)
	result.AllowsAuthenticatedACLWrite = authPerms.has(policyActionACLWrite)
	result.AllowsAuthenticatedACLRead = authPerms.has(policyActionACLRead)
}
