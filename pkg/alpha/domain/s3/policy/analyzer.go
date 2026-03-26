package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
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

		if !stmt.Effect.IsAllow() {
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
		state.updateWeakestScope(resolveConditionScope(condition))

		// Action analysis
		actionMask, _ := stmt.ResolveActions()
		if actionMask != 0 {
			res.PublicStatements = append(res.PublicStatements, stmt.StatementID(i))
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
	res.EffectiveNetworkScope = state.weakestScope

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
	weakestScope kernel.NetworkScope
	publicPerms  actionMask
	authPerms    actionMask
}

func (s *analysisState) updateWeakestScope(scope kernel.NetworkScope) {
	if s.weakestScope == kernel.NetworkScopeUnknown || scope.WeakerThan(s.weakestScope) {
		s.weakestScope = scope
	}
}

func applyPermissionMasks(res *Assessment, publicPerms, authPerms actionMask) {
	res.AllowsPublicRead = publicPerms.has(actionRead)
	res.AllowsPublicList = publicPerms.has(actionList)
	res.AllowsPublicWrite = publicPerms.has(actionWrite)
	res.AllowsPublicDelete = publicPerms.has(actionDelete)
	res.AllowsPublicACLWrite = publicPerms.has(actionACLWrite)
	res.AllowsPublicACLRead = publicPerms.has(actionACLRead)

	res.AllowsAuthenticatedRead = authPerms.has(actionRead)
	res.AllowsAuthenticatedList = authPerms.has(actionList)
	res.AllowsAuthenticatedWrite = authPerms.has(actionWrite)
	res.AllowsAuthenticatedACLWrite = authPerms.has(actionACLWrite)
	res.AllowsAuthenticatedACLRead = authPerms.has(actionACLRead)
}

func extractAccountID(arn string) (string, bool) {
	matches := accountARNPattern.FindStringSubmatch(arn)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}
