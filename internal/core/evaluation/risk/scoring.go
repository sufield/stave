package risk

// Score quantifies policy risk from 0 (Safe) to 100 (Catastrophic).
type Score int

const (
	ScoreSafe         Score = 0
	ScoreInfo         Score = 10
	ScoreWarning      Score = 40
	ScoreCritical     Score = 90
	ScoreCatastrophic Score = 100
)

// Permission is a bitmask representing generic resource capabilities.
type Permission uint32

const (
	PermRead Permission = 1 << iota
	PermWrite
	PermList
	PermAdminRead
	PermAdminWrite
	PermDelete

	PermFullControl = PermRead | PermWrite | PermList | PermAdminRead | PermAdminWrite | PermDelete
)

// Has returns true only if ALL bits in the target are present in p.
func (p Permission) Has(target Permission) bool {
	return p&target == target
}

// Overlap returns true if ANY bits in the target are present in p.
func (p Permission) Overlap(target Permission) bool {
	return p&target != 0
}

// Report represents the aggregated security posture of a policy.
type Report struct {
	Score       Score      `json:"score"`
	Findings    []string   `json:"findings"`
	IsPublic    bool       `json:"is_public"`
	Permissions Permission `json:"permissions"`
}

// StatementContext contains the attributes of a single policy statement.
type StatementContext struct {
	Permissions     Permission
	IsPublic        bool
	IsAuthenticated bool
	IsNetworkScoped bool
	IsAllow         bool
}

// ResolveActions maps raw action strings to aggregate Permission bits
// using a PermissionResolver for vendor-specific lookups.
func ResolveActions(actions []string, resolver PermissionResolver) Permission {
	var total Permission
	for _, action := range actions {
		total |= resolver.Resolve(action)
		if total == PermFullControl {
			break
		}
	}
	return total
}

// Result represents the risk contribution of a single statement.
type Result struct {
	Score    Score
	Findings []string
	IsPublic bool
}

// Evaluate analyzes the context to determine the risk level.
func (sc StatementContext) Evaluate() Result {
	if !sc.IsAllow {
		return Result{}
	}

	res := Result{}

	// 1. Evaluate Public Risk
	if sc.IsPublic && !sc.IsNetworkScoped {
		res.IsPublic = true
		// Critical: Any form of public modification
		if sc.Permissions.Overlap(PermWrite | PermAdminWrite | PermDelete) {
			res.Score = ScoreCritical
			res.Findings = append(res.Findings, "Unrestricted Public Write/Admin Access")
		} else if sc.Permissions.Has(PermRead) {
			// Warning: Public Read
			res.Score = ScoreWarning
			res.Findings = append(res.Findings, "Unrestricted Public Read Access")
		}
	}

	// 2. Evaluate Authenticated Risk
	// High risk if any authenticated user in the cloud provider has full control
	if sc.IsAuthenticated && !sc.IsPublic && sc.Permissions == PermFullControl {
		if ScoreWarning > res.Score {
			res.Score = ScoreWarning
		}
		res.Findings = append(res.Findings, "Full Admin access granted to all Authenticated Users")
	}

	return res
}

// UpdateReport merges a statement result into the main report.
func (r *Report) UpdateReport(res Result) {
	if res.Score > r.Score {
		r.Score = res.Score
	}
	if res.IsPublic {
		r.IsPublic = true
	}
	r.Findings = append(r.Findings, res.Findings...)
}
