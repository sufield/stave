package risk

import "testing"

func TestMaxScore(t *testing.T) {
	tests := []struct {
		a, b SecurityScore
		want SecurityScore
	}{
		{ScoreSafe, ScoreWarning, ScoreWarning},
		{ScoreCritical, ScoreWarning, ScoreCritical},
		{ScoreInfo, ScoreInfo, ScoreInfo},
	}
	for _, tt := range tests {
		if got := MaxScore(tt.a, tt.b); got != tt.want {
			t.Errorf("MaxScore(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestStmtPermHas(t *testing.T) {
	full := PermFullControl
	if !full.Has(PermRead) {
		t.Error("FullControl should have Read")
	}
	if !full.Has(PermWrite | PermACLWrite) {
		t.Error("FullControl should have Write|ACLWrite")
	}
	readOnly := PermRead
	if readOnly.Has(PermWrite) {
		t.Error("Read should not have Write")
	}
}

func TestAnalyzeActions(t *testing.T) {
	actionMap := map[string]StmtPerm{
		"*":               PermFullControl,
		"s3:getobject":    PermRead,
		"s3:putobject":    PermWrite,
		"s3:listbucket":   PermList,
		"s3:putobjectacl": PermACLWrite,
	}
	prefixRules := []PrefixRule{
		{Prefix: "s3:put", Perm: PermWrite},
		{Prefix: "s3:delete", Perm: PermDelete},
	}

	tests := []struct {
		name    string
		actions []string
		want    StmtPerm
	}{
		{"wildcard", []string{"*"}, PermFullControl},
		{"single read", []string{"s3:getobject"}, PermRead},
		{"write via prefix", []string{"s3:putfoo"}, PermWrite},
		{"delete via prefix", []string{"s3:deletefoo"}, PermDelete},
		{"combined", []string{"s3:getobject", "s3:putobjectacl"}, PermRead | PermWrite | PermACLWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeActions(tt.actions, actionMap, prefixRules)
			if got != tt.want {
				t.Errorf("AnalyzeActions(%v) = %v, want %v", tt.actions, got, tt.want)
			}
		})
	}
}

func TestApplyPublicStatementRisk(t *testing.T) {
	t.Run("public write", func(t *testing.T) {
		r := &Report{}
		ApplyPublicStatementRisk(StatementContext{
			Permissions: PermWrite | PermACLWrite,
			IsPublic:    true,
			Report:      r,
		})
		if r.Score != ScoreCritical {
			t.Errorf("expected critical, got %d", r.Score)
		}
		if !r.IsPublic {
			t.Error("expected IsPublic=true")
		}
	})

	t.Run("public read", func(t *testing.T) {
		r := &Report{}
		ApplyPublicStatementRisk(StatementContext{
			Permissions: PermRead,
			IsPublic:    true,
			Report:      r,
		})
		if r.Score != ScoreWarning {
			t.Errorf("expected warning, got %d", r.Score)
		}
	})

	t.Run("network scoped suppresses risk", func(t *testing.T) {
		r := &Report{}
		ApplyPublicStatementRisk(StatementContext{
			Permissions:     PermRead,
			IsPublic:        true,
			IsNetworkScoped: true,
			Report:          r,
		})
		if r.Score != ScoreSafe {
			t.Errorf("expected safe, got %d", r.Score)
		}
	})
}

func TestApplyAuthenticatedStatementRisk(t *testing.T) {
	t.Run("full control authenticated", func(t *testing.T) {
		r := &Report{}
		ApplyAuthenticatedStatementRisk(StatementContext{
			Permissions:     PermFullControl,
			IsAuthenticated: true,
			Report:          r,
		})
		if r.Score != ScoreWarning {
			t.Errorf("expected warning, got %d", r.Score)
		}
	})

	t.Run("not full control skipped", func(t *testing.T) {
		r := &Report{}
		ApplyAuthenticatedStatementRisk(StatementContext{
			Permissions:     PermRead,
			IsAuthenticated: true,
			Report:          r,
		})
		if r.Score != ScoreSafe {
			t.Errorf("expected safe, got %d", r.Score)
		}
	})
}

func TestStatementRiskEligible(t *testing.T) {
	r := &Report{}
	if StatementRiskEligible(StatementContext{Report: nil, IsAllow: true}) {
		t.Error("nil report should not be eligible")
	}
	if StatementRiskEligible(StatementContext{Report: r, IsAllow: false}) {
		t.Error("deny should not be eligible")
	}
	if !StatementRiskEligible(StatementContext{Report: r, IsAllow: true}) {
		t.Error("allow with report should be eligible")
	}
}
