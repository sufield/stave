package risk

import "testing"

func TestPermissionHas(t *testing.T) {
	full := PermFullControl
	if !full.Has(PermRead) {
		t.Error("FullControl should have Read")
	}
	if !full.Has(PermWrite | PermAdminWrite) {
		t.Error("FullControl should have Write|AdminWrite")
	}
	readOnly := PermRead
	if readOnly.Has(PermWrite) {
		t.Error("Read should not have Write")
	}
}

func TestPermissionOverlap(t *testing.T) {
	readOnly := PermRead
	if !readOnly.Overlap(PermRead | PermWrite) {
		t.Error("Read should overlap Read|Write")
	}
	if readOnly.Overlap(PermWrite | PermDelete) {
		t.Error("Read should not overlap Write|Delete")
	}
	writeDelete := PermWrite | PermDelete
	if !writeDelete.Overlap(PermWrite | PermAdminWrite | PermDelete) {
		t.Error("Write|Delete should overlap Write|AdminWrite|Delete")
	}
}

func TestAnalyzeActions(t *testing.T) {
	actionMap := map[string]Permission{
		"*":               PermFullControl,
		"s3:getobject":    PermRead,
		"s3:putobject":    PermWrite,
		"s3:listbucket":   PermList,
		"s3:putobjectacl": PermAdminWrite,
	}
	prefixRules := []PrefixRule{
		{Prefix: "s3:put", Perm: PermWrite},
		{Prefix: "s3:delete", Perm: PermDelete},
	}

	tests := []struct {
		name    string
		actions []string
		want    Permission
	}{
		{"wildcard", []string{"*"}, PermFullControl},
		{"single read", []string{"s3:getobject"}, PermRead},
		{"write via prefix", []string{"s3:putfoo"}, PermWrite},
		{"delete via prefix", []string{"s3:deletefoo"}, PermDelete},
		{"combined", []string{"s3:getobject", "s3:putobjectacl"}, PermRead | PermWrite | PermAdminWrite},
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

func TestEvaluate_PublicWrite(t *testing.T) {
	res := StatementContext{
		Permissions: PermWrite | PermAdminWrite,
		IsPublic:    true,
		IsAllow:     true,
	}.Evaluate()
	if res.Score != ScoreCritical {
		t.Errorf("expected critical, got %d", res.Score)
	}
	if !res.IsPublic {
		t.Error("expected IsPublic=true")
	}
	if len(res.Findings) != 1 || res.Findings[0] != "Unrestricted Public Write/Admin Access" {
		t.Errorf("unexpected findings: %#v", res.Findings)
	}
}

func TestEvaluate_PublicWriteOnly(t *testing.T) {
	// Overlap: even PermWrite alone should trigger critical
	res := StatementContext{
		Permissions: PermWrite,
		IsPublic:    true,
		IsAllow:     true,
	}.Evaluate()
	if res.Score != ScoreCritical {
		t.Errorf("expected critical for write-only, got %d", res.Score)
	}
}

func TestEvaluate_PublicDelete(t *testing.T) {
	// Overlap: PermDelete alone should trigger critical
	res := StatementContext{
		Permissions: PermDelete,
		IsPublic:    true,
		IsAllow:     true,
	}.Evaluate()
	if res.Score != ScoreCritical {
		t.Errorf("expected critical for delete-only, got %d", res.Score)
	}
}

func TestEvaluate_PublicRead(t *testing.T) {
	res := StatementContext{
		Permissions: PermRead,
		IsPublic:    true,
		IsAllow:     true,
	}.Evaluate()
	if res.Score != ScoreWarning {
		t.Errorf("expected warning, got %d", res.Score)
	}
}

func TestEvaluate_NetworkScopedSuppressesRisk(t *testing.T) {
	res := StatementContext{
		Permissions:     PermRead,
		IsPublic:        true,
		IsNetworkScoped: true,
		IsAllow:         true,
	}.Evaluate()
	if res.Score != ScoreSafe {
		t.Errorf("expected safe, got %d", res.Score)
	}
}

func TestEvaluate_AuthenticatedFullControl(t *testing.T) {
	res := StatementContext{
		Permissions:     PermFullControl,
		IsAuthenticated: true,
		IsAllow:         true,
	}.Evaluate()
	if res.Score != ScoreWarning {
		t.Errorf("expected warning, got %d", res.Score)
	}
	if len(res.Findings) != 1 || res.Findings[0] != "Full Admin access granted to all Authenticated Users" {
		t.Errorf("unexpected findings: %#v", res.Findings)
	}
}

func TestEvaluate_AuthenticatedPartialSkipped(t *testing.T) {
	res := StatementContext{
		Permissions:     PermRead,
		IsAuthenticated: true,
		IsAllow:         true,
	}.Evaluate()
	if res.Score != ScoreSafe {
		t.Errorf("expected safe, got %d", res.Score)
	}
}

func TestEvaluate_DenyReturnsEmpty(t *testing.T) {
	res := StatementContext{
		Permissions: PermFullControl,
		IsPublic:    true,
		IsAllow:     false,
	}.Evaluate()
	if res.Score != ScoreSafe {
		t.Errorf("expected safe for deny, got %d", res.Score)
	}
	if res.IsPublic {
		t.Error("expected IsPublic=false for deny")
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected no findings for deny, got %#v", res.Findings)
	}
}

func TestUpdateReport(t *testing.T) {
	r := &Report{}
	r.UpdateReport(Result{Score: ScoreWarning, Findings: []string{"A"}, IsPublic: true})
	r.UpdateReport(Result{Score: ScoreCritical, Findings: []string{"B"}})

	if r.Score != ScoreCritical {
		t.Errorf("expected critical, got %d", r.Score)
	}
	if !r.IsPublic {
		t.Error("expected IsPublic=true")
	}
	if len(r.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(r.Findings))
	}
}
