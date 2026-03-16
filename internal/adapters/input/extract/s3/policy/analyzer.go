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

// --- Backward-compatible entry points ---
// These delegate to Parse + Assess for callers that haven't migrated yet.

// Engine wraps a parsed Document for backward compatibility.
type Engine = Document

// NewEngine parses policy JSON and returns a Document.
func NewEngine(policyJSON string) (*Document, error) {
	return Parse(policyJSON)
}

// FullAnalysis returns the unified Assessment.
// Deprecated: use Assess() directly.
func (d *Document) FullAnalysis() Analysis {
	a := d.Assess()
	return Analysis{
		AllowsPublicRead:            a.AllowsPublicRead,
		AllowsPublicList:            a.AllowsPublicList,
		AllowsPublicWrite:           a.AllowsPublicWrite,
		AllowsPublicDelete:          a.AllowsPublicDelete,
		HasWildcardActions:          a.HasWildcardActions,
		PublicStatements:            a.PublicStatements,
		HasNetworkCondition:         a.HasNetworkCondition,
		HasIPCondition:              a.HasIPCondition,
		HasVPCCondition:             a.HasVPCCondition,
		EffectiveNetworkScope:       a.EffectiveNetworkScope,
		AllowsAuthenticatedRead:     a.AllowsAuthenticatedRead,
		AllowsAuthenticatedList:     a.AllowsAuthenticatedList,
		AllowsAuthenticatedWrite:    a.AllowsAuthenticatedWrite,
		AllowsPublicACLWrite:        a.AllowsPublicACLWrite,
		AllowsPublicACLRead:         a.AllowsPublicACLRead,
		AllowsAuthenticatedACLWrite: a.AllowsAuthenticatedACLWrite,
		AllowsAuthenticatedACLRead:  a.AllowsAuthenticatedACLRead,
	}
}

// TransportEncryptionAnalysis returns transport encryption results.
// Deprecated: use Assess().EnforcesHTTPS directly.
func (d *Document) TransportEncryptionAnalysis() TransportEncryptionAnalysis {
	return TransportEncryptionAnalysis{EnforcesHTTPS: d.Assess().EnforcesHTTPS}
}

// CrossAccountAnalysis returns cross-account access results.
// Deprecated: use Assess() directly.
func (d *Document) CrossAccountAnalysis() CrossAccountAnalysis {
	a := d.Assess()
	return CrossAccountAnalysis{
		ExternalAccountARNs: a.ExternalAccountARNs,
		ExternalAccountIDs:  a.ExternalAccountIDs,
		HasExternalAccess:   a.HasExternalAccess,
		HasExternalWrite:    a.HasExternalWrite,
	}
}

// AnalyzePolicy is a convenience function for one-off analysis.
func AnalyzePolicy(policyJSON string) Analysis {
	doc, err := Parse(policyJSON)
	if err != nil || doc == nil {
		return Analysis{}
	}
	return doc.FullAnalysis()
}

// AnalyzeTransportEncryption is a convenience function for one-off transport checks.
func AnalyzeTransportEncryption(policyJSON string) TransportEncryptionAnalysis {
	doc, err := Parse(policyJSON)
	if err != nil || doc == nil {
		return TransportEncryptionAnalysis{}
	}
	return doc.TransportEncryptionAnalysis()
}

// AnalyzeCrossAccountAccess is a convenience function for one-off cross-account checks.
func AnalyzeCrossAccountAccess(policyJSON string) CrossAccountAnalysis {
	doc, err := Parse(policyJSON)
	if err != nil || doc == nil {
		return CrossAccountAnalysis{}
	}
	return doc.CrossAccountAnalysis()
}
