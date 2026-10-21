package fieldcov

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestClassify_Evaluable(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.001",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq},
			},
		},
	}
	fields := map[string]struct{}{"properties.storage.kind": {}}
	result := classifyControl(&ctl, fields, nil, nil)
	if result.Classification != Evaluable {
		t.Errorf("classification = %q, want EVALUABLE", result.Classification)
	}
}

func TestClassify_SilentRisk_UnguardedField(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.002",
		Severity: policy.SeverityCritical,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.encryption.enabled"), Op: predicate.OpEq},
			},
		},
	}
	// Field is NOT present in snapshot.
	fields := map[string]struct{}{"properties.storage.kind": {}}
	result := classifyControl(&ctl, fields, nil, nil)
	if result.Classification != SilentRisk {
		t.Errorf("classification = %q, want SILENT_RISK", result.Classification)
	}
	if len(result.MissingFields) != 1 {
		t.Fatalf("expected 1 missing field, got %d", len(result.MissingFields))
	}
	if result.MissingFields[0] != "properties.encryption.enabled" {
		t.Errorf("missing field = %q, want properties.encryption.enabled", result.MissingFields[0])
	}
}

func TestClassify_Incomplete_MissingOperator(t *testing.T) {
	// A predicate using "missing" operator is NOT silent-risk —
	// it explicitly checks for absence.
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.003",
		Severity: policy.SeverityMedium,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.tags.env"), Op: predicate.OpMissing},
			},
		},
	}
	fields := map[string]struct{}{"properties.storage.kind": {}}
	result := classifyControl(&ctl, fields, nil, nil)
	if result.Classification != Incomplete {
		t.Errorf("classification = %q, want INCOMPLETE (missing op is not silent-risk)", result.Classification)
	}
}

func TestClassify_NoPredicate(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.004",
		Severity: policy.SeverityLow,
	}
	fields := map[string]struct{}{}
	result := classifyControl(&ctl, fields, nil, nil)
	if result.Classification != Evaluable {
		t.Errorf("classification = %q, want EVALUABLE (no predicate)", result.Classification)
	}
}

func TestCollectPresentFields(t *testing.T) {
	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					Properties: map[string]any{
						"storage": map[string]any{
							"kind": "bucket",
							"encryption": map[string]any{
								"enabled": true,
							},
						},
					},
				},
			},
		},
	}
	fields := collectPresentFields(snapshots)
	expected := []string{
		"properties.storage",
		"properties.storage.kind",
		"properties.storage.encryption",
		"properties.storage.encryption.enabled",
	}
	for _, e := range expected {
		if _, ok := fields[e]; !ok {
			t.Errorf("expected field %q to be present", e)
		}
	}
}

func TestAnalyze_FrameworkCoverage(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:       "CTL.A.001",
			Severity: policy.SeverityHigh,
			Compliance: policy.ComplianceMapping{
				"hipaa": "164.312",
			},
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.x.y"), Op: predicate.OpEq},
				},
			},
		},
		{
			ID:       "CTL.B.001",
			Severity: policy.SeverityMedium,
			Compliance: policy.ComplianceMapping{
				"hipaa": "164.308",
			},
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.x.y"), Op: predicate.OpEq},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{Properties: map[string]any{"x": map[string]any{"y": true}}},
			},
		},
	}

	report := Analyze(AnalyzeInput{
		Controls:  controls,
		Snapshots: snapshots,
	})

	if report.Summary.Evaluable != 2 {
		t.Errorf("evaluable = %d, want 2", report.Summary.Evaluable)
	}

	fc, ok := report.FrameworkCoverage["hipaa"]
	if !ok {
		t.Fatal("expected hipaa in framework coverage")
	}
	if fc.Evaluable != 2 || fc.Total != 2 {
		t.Errorf("hipaa coverage = %d/%d, want 2/2", fc.Evaluable, fc.Total)
	}
	if fc.CoveragePct != 100.0 {
		t.Errorf("hipaa coverage_pct = %.1f, want 100.0", fc.CoveragePct)
	}
}

func TestCollectRuleRefs_AnyMatch_Typed(t *testing.T) {
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.items"),
				Op:    predicate.OpAnyMatch,
				Value: policy.NewOperand(&policy.UnsafePredicate{
					All: []policy.PredicateRule{
						{Field: predicate.NewFieldPath("status"), Op: predicate.OpEq},
						{Field: predicate.NewFieldPath("owner"), Op: predicate.OpPresent},
					},
				}),
			},
		},
	}
	refs := extractFieldRefs(&pred)
	paths := make(map[string]bool)
	for _, r := range refs {
		paths[r.path] = r.silentRisk
	}
	if _, ok := paths["properties.items"]; !ok {
		t.Error("missing parent path properties.items")
	}
	if _, ok := paths["properties.items.status"]; !ok {
		t.Error("missing nested path properties.items.status")
	}
	if !paths["properties.items.status"] {
		t.Error("properties.items.status should be silent-risk (eq op)")
	}
	if _, ok := paths["properties.items.owner"]; !ok {
		t.Error("missing nested path properties.items.owner")
	}
	if paths["properties.items.owner"] {
		t.Error("properties.items.owner should NOT be silent-risk (present op)")
	}
}

func TestCollectRuleRefs_AnyMatch_RawMap(t *testing.T) {
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{
				Field: predicate.NewFieldPath("identities"),
				Op:    predicate.OpAnyMatch,
				Value: policy.NewOperand(map[string]any{
					"all": []any{
						map[string]any{"field": "type", "op": "eq", "value": "app_signer"},
						map[string]any{"field": "purpose", "op": "contains", "value": "enforce_prefix=false"},
					},
				}),
			},
		},
	}
	refs := extractFieldRefs(&pred)
	paths := make(map[string]bool)
	for _, r := range refs {
		paths[r.path] = r.silentRisk
	}
	if _, ok := paths["identities"]; !ok {
		t.Error("missing parent path identities")
	}
	if _, ok := paths["identities.type"]; !ok {
		t.Error("missing nested path identities.type")
	}
	if _, ok := paths["identities.purpose"]; !ok {
		t.Error("missing nested path identities.purpose")
	}
}

func TestCollectRuleRefs_AnyIdentityMatch_ImplicitField(t *testing.T) {
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{
				Op: predicate.OpAnyIdentityMatch,
				Value: policy.NewOperand(&policy.UnsafePredicate{
					Any: []policy.PredicateRule{
						{Field: predicate.NewFieldPath("role"), Op: predicate.OpEq},
					},
				}),
			},
		},
	}
	refs := extractFieldRefs(&pred)
	paths := make(map[string]bool)
	for _, r := range refs {
		paths[r.path] = r.silentRisk
	}
	if _, ok := paths["identities"]; !ok {
		t.Error("missing implicit parent path identities")
	}
	if _, ok := paths["identities.role"]; !ok {
		t.Error("missing nested path identities.role")
	}
}

func TestCollectRuleRefs_NoAnyMatch_Unchanged(t *testing.T) {
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq},
			{Field: predicate.NewFieldPath("properties.storage.tags.env"), Op: predicate.OpMissing},
		},
	}
	refs := extractFieldRefs(&pred)
	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs[0].path != "properties.storage.kind" || !refs[0].silentRisk {
		t.Errorf("ref[0] = %+v, want properties.storage.kind (silent-risk)", refs[0])
	}
	if refs[1].path != "properties.storage.tags.env" || refs[1].silentRisk {
		t.Errorf("ref[1] = %+v, want properties.storage.tags.env (not silent-risk)", refs[1])
	}
}

func TestCollectRuleRefs_CrossFieldOp_ExtractsTargetField(t *testing.T) {
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.storage.access.external_account_ids"),
				Op:    predicate.OpNotSubsetOfField,
				Value: policy.Str("properties.storage.access.allowed_accounts"),
			},
		},
	}
	refs := extractFieldRefs(&pred)
	paths := make(map[string]bool)
	for _, r := range refs {
		paths[r.path] = r.silentRisk
	}
	if _, ok := paths["properties.storage.access.external_account_ids"]; !ok {
		t.Error("missing primary field path")
	}
	if _, ok := paths["properties.storage.access.allowed_accounts"]; !ok {
		t.Error("missing cross-field target path")
	}
	if !paths["properties.storage.access.allowed_accounts"] {
		t.Error("cross-field target should be silent-risk")
	}
}

func TestCollectRuleRefs_CrossFieldOp_SkipsParam(t *testing.T) {
	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{
				Field:          predicate.NewFieldPath("properties.identity.policies.service_wildcards_granted"),
				Op:             predicate.OpAnyInField,
				ValueFromParam: "denied_service_wildcards",
			},
		},
	}
	refs := extractFieldRefs(&pred)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref (primary field only), got %d", len(refs))
	}
	if refs[0].path != "properties.identity.policies.service_wildcards_granted" {
		t.Errorf("ref[0] = %q, want primary field", refs[0].path)
	}
}

func TestClassify_AnyMatch_SilentRisk(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.ANYMATCH",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq},
				{
					Field: predicate.NewFieldPath("properties.items"),
					Op:    predicate.OpAnyMatch,
					Value: policy.NewOperand(&policy.UnsafePredicate{
						All: []policy.PredicateRule{
							{Field: predicate.NewFieldPath("status"), Op: predicate.OpEq},
						},
					}),
				},
			},
		},
	}
	// Parent field present, nested field missing → SILENT_RISK
	fields := map[string]struct{}{
		"properties.storage.kind": {},
		"properties.items":        {},
	}
	result := classifyControl(&ctl, fields, nil, nil)
	if result.Classification != SilentRisk {
		t.Errorf("classification = %q, want SILENT_RISK (nested field missing)", result.Classification)
	}
	found := false
	for _, f := range result.MissingFields {
		if f == "properties.items.status" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing fields %v should contain properties.items.status", result.MissingFields)
	}
}

func TestClassify_AnyMatch_Evaluable(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.ANYMATCH.OK",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{
					Field: predicate.NewFieldPath("properties.items"),
					Op:    predicate.OpAnyMatch,
					Value: policy.NewOperand(&policy.UnsafePredicate{
						All: []policy.PredicateRule{
							{Field: predicate.NewFieldPath("status"), Op: predicate.OpEq},
						},
					}),
				},
			},
		},
	}
	// Both parent and nested field present → EVALUABLE
	fields := map[string]struct{}{
		"properties.items":        {},
		"properties.items.status": {},
	}
	result := classifyControl(&ctl, fields, nil, nil)
	if result.Classification != Evaluable {
		t.Errorf("classification = %q, want EVALUABLE", result.Classification)
	}
}
