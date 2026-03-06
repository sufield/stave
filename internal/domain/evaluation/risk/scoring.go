package risk

// SecurityScore quantifies policy risk from 0-100.
type SecurityScore int

const (
	ScoreSafe         SecurityScore = 0
	ScoreInfo         SecurityScore = 10
	ScoreWarning      SecurityScore = 40
	ScoreCritical     SecurityScore = 90
	ScoreCatastrophic SecurityScore = 100
)

// MaxScore returns the higher of two scores.
func MaxScore(a, b SecurityScore) SecurityScore {
	if a > b {
		return a
	}
	return b
}

// StmtPerm is a statement-level permission bitmask.
type StmtPerm uint32

const (
	PermRead StmtPerm = 1 << iota
	PermWrite
	PermList
	PermACLRead
	PermACLWrite
	PermDelete

	PermFullControl = PermRead | PermWrite | PermList | PermACLRead | PermACLWrite | PermDelete
)

// Has returns true when all bits in target are present.
func (p StmtPerm) Has(target StmtPerm) bool {
	return p&target == target
}

// Report is the aggregated result of policy risk evaluation.
type Report struct {
	Score       SecurityScore `json:"score"`
	Findings    []string      `json:"findings"`
	IsPublic    bool          `json:"is_public"`
	Permissions StmtPerm      `json:"permissions"`
}

// StatementContext bundles all inputs needed to evaluate a single
// policy statement's contribution to report risk.
type StatementContext struct {
	Permissions     StmtPerm
	IsPublic        bool
	IsAuthenticated bool
	IsNetworkScoped bool
	IsAllow         bool
	Report          *Report
}

// AnalyzeActions maps action strings to aggregate permission bits using the provided action map.
func AnalyzeActions(actions []string, actionMap map[string]StmtPerm, prefixRules []PrefixRule) StmtPerm {
	var total StmtPerm
	for _, action := range actions {
		if p, ok := actionMap[action]; ok {
			total |= p
		}
		for _, rule := range prefixRules {
			if len(action) >= len(rule.Prefix) && action[:len(rule.Prefix)] == rule.Prefix {
				total |= rule.Perm
			}
		}
		if total == PermFullControl {
			break
		}
	}
	return total
}

// PrefixRule maps an action prefix to a permission.
type PrefixRule struct {
	Prefix string
	Perm   StmtPerm
}

// StatementRiskEligible returns true when the statement should be scored.
func StatementRiskEligible(ctx StatementContext) bool {
	if ctx.Report == nil {
		return false
	}
	return ctx.IsAllow
}

// ApplyStatementRisk applies both public and authenticated risk scoring.
func ApplyStatementRisk(ctx StatementContext) {
	if !StatementRiskEligible(ctx) {
		return
	}
	ApplyPublicStatementRisk(ctx)
	ApplyAuthenticatedStatementRisk(ctx)
}

// ApplyPublicStatementRisk scores public access risk.
func ApplyPublicStatementRisk(ctx StatementContext) {
	if !ctx.IsPublic || ctx.IsNetworkScoped {
		return
	}
	ctx.Report.IsPublic = true
	if ctx.Permissions.Has(PermWrite | PermACLWrite) {
		ctx.Report.Score = MaxScore(ctx.Report.Score, ScoreCritical)
		ctx.Report.Findings = append(ctx.Report.Findings, "Unrestricted Public Write/ACL Access")
		return
	}
	if ctx.Permissions.Has(PermRead) {
		ctx.Report.Score = MaxScore(ctx.Report.Score, ScoreWarning)
		ctx.Report.Findings = append(ctx.Report.Findings, "Unrestricted Public Read Access")
	}
}

// ApplyAuthenticatedStatementRisk scores authenticated full-control risk.
func ApplyAuthenticatedStatementRisk(ctx StatementContext) {
	if !ctx.IsAuthenticated || ctx.IsPublic || ctx.Permissions != PermFullControl {
		return
	}
	ctx.Report.Score = MaxScore(ctx.Report.Score, ScoreWarning)
	ctx.Report.Findings = append(ctx.Report.Findings, "Full Admin access granted to Authenticated Users")
}
