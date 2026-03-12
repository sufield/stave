package policy

import (
	"encoding/json"
	"strings"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
)

// Re-export score constants.
const (
	ScoreSafe         = risk.ScoreSafe
	ScoreInfo         = risk.ScoreInfo
	ScoreWarning      = risk.ScoreWarning
	ScoreCritical     = risk.ScoreCritical
	ScoreCatastrophic = risk.ScoreCatastrophic
)

// Re-export permission constants.
const (
	PermRead        = risk.PermRead
	PermWrite       = risk.PermWrite
	PermList        = risk.PermList
	PermAdminRead   = risk.PermAdminRead
	PermAdminWrite  = risk.PermAdminWrite
	PermDelete      = risk.PermDelete
	PermFullControl = risk.PermFullControl
)

// Evaluator encapsulates policy scoring rules.
type Evaluator struct {
	TrustedCIDRs []string
}

var evaluatorActionMap = map[string]risk.Permission{
	policyWildcard:                 risk.PermFullControl,
	policyS3Wildcard:               risk.PermFullControl,
	policyActionGetObject:          risk.PermRead,
	policyActionPutObject:          risk.PermWrite,
	policyActionListBucket:         risk.PermList,
	policyActionGetBucketACL:       risk.PermAdminRead,
	policyActionGetObjectACL:       risk.PermAdminRead,
	policyActionPutBucketACL:       risk.PermAdminWrite,
	policyActionPutObjectACL:       risk.PermAdminWrite,
	policyActionDeleteObject:       risk.PermDelete,
	policyActionDeleteBucket:       risk.PermDelete,
	policyActionListBucketVersions: risk.PermList,
}

var evaluatorPrefixRules = []risk.PrefixRule{
	{Prefix: policyActionPrefixPut, Perm: risk.PermWrite},
	{Prefix: policyActionPrefixDelete, Perm: risk.PermDelete},
}

// NewEvaluator constructs a new policy evaluator.
func NewEvaluator(trusted []string) *Evaluator {
	return &Evaluator{TrustedCIDRs: trusted}
}

// ParseIAMPolicy parses raw IAM policy JSON.
func ParseIAMPolicy(jsonPolicy string) (BucketPolicy, error) {
	var policy BucketPolicy
	if err := json.Unmarshal([]byte(jsonPolicy), &policy); err != nil {
		return BucketPolicy{}, err
	}
	return policy, nil
}

// IsNetworkScoped returns true when condition restricts by IP/VPC/Org.
func IsNetworkScoped(condition any) bool {
	analysis := analyzeCondition(condition)
	return analysis.HasIPCondition || analysis.HasVPCCondition || analysis.HasOrgCondition
}

// Evaluate computes a policy risk report from raw JSON.
func (e *Evaluator) Evaluate(jsonPolicy string) risk.Report {
	policy, err := ParseIAMPolicy(jsonPolicy)
	if err != nil {
		return risk.Report{
			Score:    risk.ScoreCatastrophic,
			Findings: []string{"Malformed JSON Policy"},
		}
	}

	report := risk.Report{}

	for _, stmt := range policy.Statement {
		if stmt.Effect != "" && !stmt.Effect.IsAllow() {
			continue
		}

		actions := normalizeActions([]string(stmt.Action))
		perms := risk.AnalyzeActions(actions, evaluatorActionMap, evaluatorPrefixRules)
		report.Permissions |= perms

		isPublic, isAuth := classifyPolicyPrincipal(stmt.principalAny())
		isNetworkScoped := IsNetworkScoped(stmt.conditionAny())
		ctx := risk.StatementContext{
			Permissions:     perms,
			IsPublic:        isPublic,
			IsAuthenticated: isAuth,
			IsNetworkScoped: isNetworkScoped,
			IsAllow:         stmt.Effect == "" || stmt.Effect.IsAllow(),
		}
		report.UpdateReport(ctx.Evaluate())
	}

	return report
}

func classifyPolicyPrincipal(principal any) (isPublic bool, isAuthenticated bool) {
	return IsPublicPrincipal(principal), isAuthenticatedPrincipal(principal)
}

func normalizeActions(actions []string) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = strings.ToLower(a)
	}
	return out
}
