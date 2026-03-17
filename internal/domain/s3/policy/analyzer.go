package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/sufield/stave/internal/domain/kernel"
)

var accountARNPattern = regexp.MustCompile(`^arn:aws:iam::(\d{12}):`)

// Assessment is the unified security posture derived from a bucket policy.
// It consolidates access, transport, cross-account, and network analysis
// into a single result produced in one pass.
type Assessment struct {
	// Public exposure
	AllowsPublicRead   bool                 `json:"allows_public_read"`
	AllowsPublicList   bool                 `json:"allows_public_list"`
	AllowsPublicWrite  bool                 `json:"allows_public_write"`
	AllowsPublicDelete bool                 `json:"allows_public_delete"`
	HasWildcardActions bool                 `json:"has_wildcard_actions"`
	PublicStatements   []kernel.StatementID `json:"public_statements"`

	// Network conditions
	HasNetworkCondition   bool                `json:"has_network_condition"`
	HasIPCondition        bool                `json:"has_ip_condition"`
	HasVPCCondition       bool                `json:"has_vpc_condition"`
	EffectiveNetworkScope kernel.NetworkScope `json:"effective_network_scope"`

	// Authenticated-only principal access
	AllowsAuthenticatedRead  bool `json:"allows_authenticated_read"`
	AllowsAuthenticatedList  bool `json:"allows_authenticated_list"`
	AllowsAuthenticatedWrite bool `json:"allows_authenticated_write"`

	// ACL-specific actions via bucket policy
	AllowsPublicACLWrite        bool `json:"allows_public_acl_write"`
	AllowsPublicACLRead         bool `json:"allows_public_acl_read"`
	AllowsAuthenticatedACLWrite bool `json:"allows_authenticated_acl_write"`
	AllowsAuthenticatedACLRead  bool `json:"allows_authenticated_acl_read"`

	// Transport encryption
	EnforcesHTTPS bool `json:"enforces_https"`

	// Cross-account access
	HasExternalAccess   bool     `json:"has_external_access"`
	HasExternalWrite    bool     `json:"has_external_write"`
	ExternalAccountARNs []string `json:"external_account_arns"`
	ExternalAccountIDs  []string `json:"external_account_ids"`
}

// Document is the parsed bucket policy. It is created once via Parse
// and provides Assess() as the single entry point for analysis.
type Document struct {
	statements []Statement
}

// Parse turns raw policy JSON into a typed Document.
func Parse(policyJSON string) (*Document, error) {
	if policyJSON == "" {
		return &Document{}, nil
	}
	var raw BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &raw); err != nil {
		return nil, fmt.Errorf("invalid bucket policy JSON: %w", err)
	}
	return &Document{statements: raw.Statement}, nil
}

// Assess performs a comprehensive security analysis in a single pass,
// producing transport, access, cross-account, and network results.
func (d *Document) Assess() Assessment {
	var res Assessment
	state := analysisState{}

	for i, stmt := range d.statements {
		if stmt.EnforcesHTTPS() {
			res.EnforcesHTTPS = true
		}

		if !stmt.IsAllow() {
			continue
		}

		scope := stmt.PrincipalScope()

		// Cross-account analysis
		if scope == kernel.ScopeAccount {
			d.extractExternalAccounts(&res, stmt)
			continue
		}

		// Network condition analysis
		condition := stmt.ConditionAnalysis()
		if condition.IsNetworkScoped() {
			res.HasNetworkCondition = true
			res.HasIPCondition = res.HasIPCondition || condition.HasIPCondition
			res.HasVPCCondition = res.HasVPCCondition || condition.HasVPCCondition
		}
		state.updateWeakestScope(conditionScope(condition))

		// Action analysis
		actionMask, _ := stmt.ResolveActions()
		if actionMask != 0 {
			res.PublicStatements = append(res.PublicStatements, stmt.ID(i))
		}
		res.HasWildcardActions = res.HasWildcardActions || stmt.HasWildcardActionsOnWildcardResources()

		// Permission accumulation
		switch {
		case stmt.IsPubliclyExposed():
			if !condition.IsNetworkScoped() {
				state.publicPerms |= actionMask
			}
		case scope == kernel.ScopeAuthenticated:
			state.authPerms |= actionMask
		}
	}

	applyPermissionMasks(&res, state.publicPerms, state.authPerms)
	res.EffectiveNetworkScope = toKernelNetworkScope(state.weakestScope)

	return res
}

func (d *Document) extractExternalAccounts(res *Assessment, stmt Statement) {
	arns := stmt.PrincipalARNs()
	for _, arn := range arns {
		if id, ok := extractAccountID(arn); ok {
			if !slices.Contains(res.ExternalAccountIDs, id) {
				res.ExternalAccountIDs = append(res.ExternalAccountIDs, id)
				res.ExternalAccountARNs = append(res.ExternalAccountARNs, arn)
			}
		}
	}
	if len(arns) > 0 {
		res.HasExternalAccess = true
		if stmt.HasWriteActions() {
			res.HasExternalWrite = true
		}
	}
}

type analysisState struct {
	weakestScope networkScope
	publicPerms  policyActionMask
	authPerms    policyActionMask
}

func (s *analysisState) updateWeakestScope(scope networkScope) {
	if s.weakestScope == "" || scope.weakerThan(s.weakestScope) {
		s.weakestScope = scope
	}
}

func applyPermissionMasks(res *Assessment, publicPerms, authPerms policyActionMask) {
	res.AllowsPublicRead = publicPerms.has(policyActionRead)
	res.AllowsPublicList = publicPerms.has(policyActionList)
	res.AllowsPublicWrite = publicPerms.has(policyActionWrite)
	res.AllowsPublicDelete = publicPerms.has(policyActionDelete)
	res.AllowsPublicACLWrite = publicPerms.has(policyActionACLWrite)
	res.AllowsPublicACLRead = publicPerms.has(policyActionACLRead)

	res.AllowsAuthenticatedRead = authPerms.has(policyActionRead)
	res.AllowsAuthenticatedList = authPerms.has(policyActionList)
	res.AllowsAuthenticatedWrite = authPerms.has(policyActionWrite)
	res.AllowsAuthenticatedACLWrite = authPerms.has(policyActionACLWrite)
	res.AllowsAuthenticatedACLRead = authPerms.has(policyActionACLRead)
}

func extractAccountID(arn string) (string, bool) {
	matches := accountARNPattern.FindStringSubmatch(arn)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}
