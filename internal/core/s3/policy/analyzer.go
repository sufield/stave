package policy

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/sufield/stave/internal/core/kernel"
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
	HasExternalAccess   bool            `json:"has_external_access"`
	HasExternalWrite    bool            `json:"has_external_write"`
	ExternalAccountARNs []AWSAccountARN `json:"external_account_arns"`
	ExternalAccountIDs  []AWSAccountID  `json:"external_account_ids"`
}

// Document is the parsed bucket policy. Created once via Parse;
// provides Assess() as the single entry point for analysis.
type Document struct {
	statements []Statement
}

// Parse turns raw policy JSON into a typed Document.
func Parse(policyJSON string) (*Document, error) {
	if policyJSON == "" || policyJSON == "{}" {
		return &Document{}, nil
	}
	var raw BucketPolicy
	if err := json.Unmarshal([]byte(policyJSON), &raw); err != nil {
		return nil, fmt.Errorf("invalid bucket policy JSON: %w", err)
	}
	return &Document{statements: raw.Statement}, nil
}

// Assess performs a comprehensive security analysis in a single pass.
func (d *Document) Assess() Assessment {
	res := Assessment{
		PublicStatements:   []kernel.StatementID{},
		ExternalAccountIDs: []AWSAccountID{},
	}
	state := &analysisState{
		seenAccounts: make(map[string]struct{}),
	}

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
			analyzeExternalAccess(&res, state, stmt)
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
		mask, _ := stmt.ResolveActions()
		if mask != 0 {
			res.PublicStatements = append(res.PublicStatements, stmt.StatementID(i))
		}
		res.HasWildcardActions = res.HasWildcardActions || stmt.HasWildcardActionsOnWildcardResources()

		// Permission accumulation by scope
		switch {
		case stmt.IsPubliclyExposed():
			if !condition.IsNetworkScoped() {
				state.publicPerms |= mask
			}
		case scope == kernel.ScopeAuthenticated:
			state.authPerms |= mask
		}
	}

	res.applyMasks(state)
	return res
}

// analyzeExternalAccess extracts cross-account ARNs and tracks unique
// account IDs using a set for O(1) dedup instead of O(n) slice search.
func analyzeExternalAccess(res *Assessment, state *analysisState, stmt Statement) {
	arns := stmt.PrincipalARNs()
	if len(arns) == 0 {
		return
	}

	res.HasExternalAccess = true

	mask, _ := stmt.ResolveActions()
	if mask.has(actionWrite) || mask.has(actionDelete) || mask.has(actionACLWrite) {
		res.HasExternalWrite = true
	}

	for _, arn := range arns {
		id, ok := extractAccountID(arn)
		if !ok {
			continue
		}
		if _, seen := state.seenAccounts[string(id)]; seen {
			continue
		}
		state.seenAccounts[string(id)] = struct{}{}
		res.ExternalAccountIDs = append(res.ExternalAccountIDs, id)
		res.ExternalAccountARNs = append(res.ExternalAccountARNs, AWSAccountARN(arn))
	}
}

type analysisState struct {
	weakestScope kernel.NetworkScope
	publicPerms  actionMask
	authPerms    actionMask
	seenAccounts map[string]struct{}
}

func (s *analysisState) updateWeakestScope(scope kernel.NetworkScope) {
	if s.weakestScope == kernel.NetworkScopeUnknown || scope.WeakerThan(s.weakestScope) {
		s.weakestScope = scope
	}
}

func (r *Assessment) applyMasks(state *analysisState) {
	r.EffectiveNetworkScope = state.weakestScope

	r.AllowsPublicRead = state.publicPerms.has(actionRead)
	r.AllowsPublicList = state.publicPerms.has(actionList)
	r.AllowsPublicWrite = state.publicPerms.has(actionWrite)
	r.AllowsPublicDelete = state.publicPerms.has(actionDelete)
	r.AllowsPublicACLWrite = state.publicPerms.has(actionACLWrite)
	r.AllowsPublicACLRead = state.publicPerms.has(actionACLRead)

	r.AllowsAuthenticatedRead = state.authPerms.has(actionRead)
	r.AllowsAuthenticatedList = state.authPerms.has(actionList)
	r.AllowsAuthenticatedWrite = state.authPerms.has(actionWrite)
	r.AllowsAuthenticatedACLWrite = state.authPerms.has(actionACLWrite)
	r.AllowsAuthenticatedACLRead = state.authPerms.has(actionACLRead)
}

func extractAccountID(arn string) (AWSAccountID, bool) {
	matches := accountARNPattern.FindStringSubmatch(arn)
	if len(matches) < 2 {
		return "", false
	}
	return AWSAccountID(matches[1]), true
}
