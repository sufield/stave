package controldef

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// Prepare edge cases
// ---------------------------------------------------------------------------

func TestControlDefinitionPrepareNoDuration(t *testing.T) {
	ctl := ControlDefinition{
		Params: NewParams(map[string]any{"some_key": "val"}),
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("Prepare() err = %v", err)
	}
	if !ctl.Prepared.Ready {
		t.Fatal("should be ready")
	}
	if ctl.Prepared.HasMaxUnsafeDuration {
		t.Fatal("HasMaxUnsafeDuration should be false when param not set")
	}
	if ctl.Prepared.MaxUnsafeDuration != 0 {
		t.Fatalf("MaxUnsafeDuration should be 0, got %v", ctl.Prepared.MaxUnsafeDuration)
	}
}

func TestControlDefinitionPrepareWithRecurrence(t *testing.T) {
	ctl := ControlDefinition{
		Params: NewParams(map[string]any{
			"recurrence_limit": 5,
			"window_days":      14,
		}),
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("Prepare() err = %v", err)
	}
	rp := ctl.RecurrencePolicy()
	if rp.Limit != 5 || rp.WindowDays != 14 {
		t.Fatalf("recurrence policy: %+v", rp)
	}
}

func TestControlDefinitionPrepareWithPrefixExposure(t *testing.T) {
	ctl := ControlDefinition{
		Params: NewParams(map[string]any{
			"allowed_public_prefixes": []string{"public/", "static/"},
			"protected_prefixes":      []string{"private/"},
		}),
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("Prepare() err = %v", err)
	}
	pe := ctl.ExposurePrefixes()
	if pe.AllowedPublicPrefixes.Empty() {
		t.Fatal("AllowedPublicPrefixes should not be empty")
	}
	if pe.ProtectedPrefixes.Empty() {
		t.Fatal("ProtectedPrefixes should not be empty")
	}
}

func TestControlDefinitionMaxUnsafeDuration(t *testing.T) {
	ctl := ControlDefinition{}
	got := ctl.MaxUnsafeDuration()
	if got != 0 {
		t.Fatalf("expected 0, got %v", got)
	}
}

func TestControlDefinitionEnsurePreparedLazy(t *testing.T) {
	ctl := ControlDefinition{
		Params: NewParams(map[string]any{"max_unsafe_duration": "48h"}),
	}
	// Access accessor without calling Prepare()
	d := ctl.MaxUnsafeDuration()
	if d != 48*time.Hour {
		t.Fatalf("expected 48h, got %v", d)
	}
	if !ctl.Prepared.Ready {
		t.Fatal("ensurePrepared should have called Prepare()")
	}
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

func TestCatalogPackHashNil(t *testing.T) {
	var cat *Catalog
	if cat.PackHash(nil) != "" {
		t.Fatal("nil catalog PackHash should return empty digest")
	}
}

func TestCatalogPackHashEmpty(t *testing.T) {
	cat := NewCatalog(nil)
	if cat.PackHash(nil) != "" {
		t.Fatal("empty catalog PackHash should return empty digest")
	}
}

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

func TestValidateControlDefinitionNil(t *testing.T) {
	issues := ValidateControlDefinition(nil)
	if len(issues) != 0 {
		t.Fatalf("nil control should produce no issues, got %d", len(issues))
	}
}

func TestValidateControlDefinitionMissingMetadata(t *testing.T) {
	ctl := &ControlDefinition{}
	issues := ValidateControlDefinition(ctl)
	// Should have issues for missing ID, name, description, and empty predicate
	if len(issues) < 3 {
		t.Fatalf("expected at least 3 issues for empty control, got %d", len(issues))
	}
}

func TestValidateControlDefinitionBadIDFormat(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("BADFORMAT"),
		Name:        "test",
		Description: "test desc",
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasBadID := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_ID_FORMAT" {
			hasBadID = true
		}
	}
	if !hasBadID {
		t.Fatal("expected CONTROL_BAD_ID_FORMAT issue")
	}
}

func TestValidateControlDefinitionBadSeverity(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.SEV.001"),
		Name:        "test",
		Description: "test desc",
		Severity:    Severity(99),
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasBadSev := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_SEVERITY" {
			hasBadSev = true
		}
	}
	if !hasBadSev {
		t.Fatal("expected CONTROL_BAD_SEVERITY issue")
	}
}

func TestValidateControlDefinitionBadType(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.TYPE.001"),
		Name:        "test",
		Description: "test desc",
		Type:        ControlType(99),
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasBadType := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_TYPE" {
			hasBadType = true
		}
	}
	if !hasBadType {
		t.Fatal("expected CONTROL_BAD_TYPE issue")
	}
}

func TestValidateControlDefinitionEmptyPredicate(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.EMPTY.001"),
		Name:        "test",
		Description: "test desc",
	}
	issues := ValidateControlDefinition(ctl)
	hasEmptyPred := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_EMPTY_PREDICATE" {
			hasEmptyPred = true
		}
	}
	if !hasEmptyPred {
		t.Fatal("expected CONTROL_EMPTY_PREDICATE issue")
	}
}

func TestValidateControlDefinitionUnsupportedOperator(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.OP.001"),
		Name:        "test",
		Description: "test desc",
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{
				{Field: predicate.NewFieldPath("f"), Op: predicate.Operator("bogus_op"), Value: Bool(true)},
			},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasUnsupportedOp := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_UNSUPPORTED_OPERATOR" {
			hasUnsupportedOp = true
		}
	}
	if !hasUnsupportedOp {
		t.Fatal("expected CONTROL_UNSUPPORTED_OPERATOR issue")
	}
}

func TestValidateControlDefinitionUndefinedParam(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.PARAM.001"),
		Name:        "test",
		Description: "test desc",
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{
				{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, ValueFromParam: predicate.ParamRef("missing_key")},
			},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasUndefined := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_UNDEFINED_PARAM" {
			hasUndefined = true
		}
	}
	if !hasUndefined {
		t.Fatal("expected CONTROL_UNDEFINED_PARAM issue")
	}
}

func TestValidateControlDefinitionBadDurationParam(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.DUR.001"),
		Name:        "test",
		Description: "test desc",
		Params:      NewParams(map[string]any{"max_unsafe_duration": "invalid-dur"}),
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasBadDur := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_DURATION_PARAM" {
			hasBadDur = true
		}
	}
	if !hasBadDur {
		t.Fatal("expected CONTROL_BAD_DURATION_PARAM issue")
	}
}

func TestValidateControlDefinitionEmptyDurationParam(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.DUR.002"),
		Name:        "test",
		Description: "test desc",
		Params:      NewParams(map[string]any{"max_unsafe_duration": 123}), // not a string
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	hasBadDur := false
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_DURATION_PARAM" {
			hasBadDur = true
		}
	}
	if !hasBadDur {
		t.Fatal("expected CONTROL_BAD_DURATION_PARAM for non-string duration")
	}
}

func TestValidateControlDefinitionValidDuration(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.DUR.003"),
		Name:        "test",
		Description: "test desc",
		Params:      NewParams(map[string]any{"max_unsafe_duration": "7d"}),
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_DURATION_PARAM" {
			t.Fatal("should not have CONTROL_BAD_DURATION_PARAM for valid duration")
		}
	}
}

func TestValidateControlDefinitionSeverityNoneAccepted(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.SEVNONE.001"),
		Name:        "test",
		Description: "test desc",
		Severity:    SeverityNone,
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_SEVERITY" {
			t.Fatal("SeverityNone should be accepted")
		}
	}
}

func TestValidateControlDefinitionTypeUnknownAccepted(t *testing.T) {
	ctl := &ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.TYPEUNK.001"),
		Name:        "test",
		Description: "test desc",
		Type:        TypeUnknown,
		UnsafePredicate: UnsafePredicate{
			Any: []PredicateRule{{Field: predicate.NewFieldPath("f"), Op: predicate.OpEq, Value: Bool(true)}},
		},
	}
	issues := ValidateControlDefinition(ctl)
	for _, issue := range issues {
		if issue.Code == "CONTROL_BAD_TYPE" {
			t.Fatal("TypeUnknown should be accepted")
		}
	}
}

// ---------------------------------------------------------------------------
// CheckEffectiveness
// ---------------------------------------------------------------------------

func TestCheckEffectivenessNilEval(t *testing.T) {
	issues := CheckEffectiveness(nil, nil, nil)
	if len(issues) != 0 {
		t.Fatal("nil eval should return no issues")
	}
}

func TestCheckEffectivenessNeverTriggered(t *testing.T) {
	controls := []ControlDefinition{
		{ID: kernel.ControlID("CTL.TEST.001"), Name: "test"},
	}
	snapshots := []asset.Snapshot{}
	eval := func(_ ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
	issues := CheckEffectiveness(controls, snapshots, eval)
	if len(issues) != 1 {
		t.Fatalf("expected 1 issue, got %d", len(issues))
	}
}

func TestCheckEffectivenessTriggered(t *testing.T) {
	controls := []ControlDefinition{
		{ID: kernel.ControlID("CTL.TEST.001"), Name: "test"},
	}
	snapshots := []asset.Snapshot{
		{Assets: []asset.Asset{{ID: "a1"}}},
	}
	eval := func(_ ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil
	}
	issues := CheckEffectiveness(controls, snapshots, eval)
	if len(issues) != 0 {
		t.Fatalf("expected 0 issues for triggered control, got %d", len(issues))
	}
}

// ---------------------------------------------------------------------------
// ExtractMisconfigurations
// ---------------------------------------------------------------------------

func TestExtractMisconfigurationsNil(t *testing.T) {
	result := ExtractMisconfigurations(nil, nil)
	if result != nil {
		t.Fatal("nil predicate should return nil")
	}
}

func TestExtractMisconfigurationsEmpty(t *testing.T) {
	pred := &UnsafePredicate{}
	ctx := &EvalContext{Properties: map[string]any{}}
	result := ExtractMisconfigurations(pred, ctx)
	if result != nil {
		t.Fatal("empty predicate should return nil")
	}
}

func TestExtractMisconfigurationsSorted(t *testing.T) {
	pred := &UnsafePredicate{
		Any: []PredicateRule{
			{Field: predicate.NewFieldPath("properties.z_field"), Op: predicate.OpEq, Value: Bool(true)},
			{Field: predicate.NewFieldPath("properties.a_field"), Op: predicate.OpEq, Value: Bool(false)},
		},
	}
	ctx := &EvalContext{
		Properties: map[string]any{
			"z_field": true,
			"a_field": false,
		},
	}
	results := ExtractMisconfigurations(pred, ctx)
	if len(results) != 2 {
		t.Fatalf("expected 2 misconfigurations, got %d", len(results))
	}
	// Should be sorted by Property
	if results[0].Property.String() != "a_field" {
		t.Fatalf("expected a_field first, got %s", results[0].Property)
	}
}

func TestExtractMisconfigurationsDedup(t *testing.T) {
	pred := &UnsafePredicate{
		Any: []PredicateRule{
			{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: Bool(true)},
		},
		All: []PredicateRule{
			{Field: predicate.NewFieldPath("properties.x"), Op: predicate.OpEq, Value: Bool(true)},
		},
	}
	ctx := &EvalContext{
		Properties: map[string]any{"x": true},
	}
	results := ExtractMisconfigurations(pred, ctx)
	if len(results) != 1 {
		t.Fatalf("expected 1 after dedup, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// ExpiryDate UnmarshalText
// ---------------------------------------------------------------------------

func TestExpiryDateUnmarshalText(t *testing.T) {
	var d ExpiryDate
	if err := d.UnmarshalText([]byte("2026-03-15")); err != nil {
		t.Fatal(err)
	}
	if d.String() != "2026-03-15" {
		t.Fatalf("got %q", d.String())
	}

	// null
	var d2 ExpiryDate
	if err := d2.UnmarshalText([]byte("null")); err != nil {
		t.Fatal(err)
	}
	if !d2.IsZero() {
		t.Fatal("null should result in zero")
	}

	// empty
	var d3 ExpiryDate
	if err := d3.UnmarshalText([]byte("")); err != nil {
		t.Fatal(err)
	}
	if !d3.IsZero() {
		t.Fatal("empty should result in zero")
	}

	// bad
	var d4 ExpiryDate
	if err := d4.UnmarshalText([]byte("bad-date")); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// ExceptionConfig with expired rule
// ---------------------------------------------------------------------------

func TestExceptionConfigExpiredRule(t *testing.T) {
	expires, _ := ParseExpiryDate("2026-01-01")
	rules := []ExceptionRule{
		{ControlID: "CTL.TEST.001", AssetID: "bucket-a", Reason: "expired", Expires: expires},
	}
	cfg := NewExceptionConfig(rules)
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC) // past expiry

	r := cfg.ShouldExcept("CTL.TEST.001", "bucket-a", now)
	if r != nil {
		t.Fatal("expired rule should not match")
	}
}

// ---------------------------------------------------------------------------
// Severity YAML marshal/unmarshal
// ---------------------------------------------------------------------------

func TestSeverityMarshalYAML(t *testing.T) {
	v, err := SeverityHigh.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	if v != "high" {
		t.Fatalf("MarshalYAML = %v, want 'high'", v)
	}
}

func TestSeverityUnmarshalYAML(t *testing.T) {
	var s Severity
	err := s.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "medium"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if s != SeverityMedium {
		t.Fatalf("got %v, want SeverityMedium", s)
	}
}

// ---------------------------------------------------------------------------
// ControlType YAML marshal/unmarshal
// ---------------------------------------------------------------------------

func TestControlTypeMarshalText(t *testing.T) {
	b, err := TypeUnsafeDuration.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "unsafe_duration" {
		t.Fatalf("got %q", string(b))
	}
}

func TestControlTypeUnmarshalText(t *testing.T) {
	var ct ControlType
	if err := ct.UnmarshalText([]byte("prefix_exposure")); err != nil {
		t.Fatal(err)
	}
	if ct != TypePrefixExposure {
		t.Fatalf("got %v, want TypePrefixExposure", ct)
	}
}

func TestControlTypeMarshalYAML(t *testing.T) {
	v, err := TypeUnsafeState.MarshalYAML()
	if err != nil {
		t.Fatal(err)
	}
	if v != "unsafe_state" {
		t.Fatalf("MarshalYAML = %v", v)
	}
}

func TestControlTypeUnmarshalYAML(t *testing.T) {
	var ct ControlType
	err := ct.UnmarshalYAML(func(v any) error {
		*(v.(*string)) = "unsafe_recurrence"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ct != TypeUnsafeRecurrence {
		t.Fatalf("got %v, want TypeUnsafeRecurrence", ct)
	}
}

// ---------------------------------------------------------------------------
// Misconfiguration String fallback
// ---------------------------------------------------------------------------

func TestMisconfigurationStringDefaultOperator(t *testing.T) {
	m := Misconfiguration{
		Property:    predicate.NewFieldPath("properties.x"),
		Operator:    predicate.Operator("custom_op"),
		ActualValue: "val",
	}
	got := m.String()
	if got == "" {
		t.Fatal("expected non-empty string")
	}
}

// ---------------------------------------------------------------------------
// ControlParams JSON round-trip with values
// ---------------------------------------------------------------------------

func TestControlParamsJSONRoundTrip(t *testing.T) {
	p := NewParams(map[string]any{"key": "value", "num": float64(42)})
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var p2 ControlParams
	if err := json.Unmarshal(data, &p2); err != nil {
		t.Fatal(err)
	}
	if p2.Len() != 2 {
		t.Fatalf("expected 2 params, got %d", p2.Len())
	}
}

// ---------------------------------------------------------------------------
// PrefixSet overlap reversed containment
// ---------------------------------------------------------------------------

func TestPrefixSetOverlapReversedContainment(t *testing.T) {
	allowed := NewPrefixSet("public/images/secret")
	protected := NewPrefixSet("public/images")

	conflict := allowed.Overlap(protected)
	if conflict == nil {
		t.Fatal("expected overlap")
	}
}

func TestPrefixSetOverlapNoOverlap(t *testing.T) {
	a := NewPrefixSet("alpha")
	b := NewPrefixSet("beta")
	if a.Overlap(b) != nil {
		t.Fatal("no overlap expected")
	}
}

// ---------------------------------------------------------------------------
// StableRemediationPlanID
// ---------------------------------------------------------------------------

type mockIDGen struct{}

func (mockIDGen) GenerateID(prefix string, components ...string) string {
	var result strings.Builder
	result.WriteString(prefix)
	for _, p := range components {
		result.WriteString("-" + p)
	}
	return result.String()
}

func TestStableRemediationPlanID(t *testing.T) {
	gen := mockIDGen{}
	id := StableRemediationPlanID(gen, kernel.ControlID("CTL.TEST.001"), asset.ID("bucket-a"))
	if id == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestStableRemediationGroupID(t *testing.T) {
	gen := mockIDGen{}
	id := StableRemediationGroupID(gen, asset.ID("bucket-a"), "hash123")
	if id == "" {
		t.Fatal("expected non-empty ID")
	}
}
