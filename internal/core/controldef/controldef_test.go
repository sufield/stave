package controldef

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

func TestSeverityString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityNone, ""},
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), ""},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityIsValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  Severity
		want bool
	}{
		{SeverityNone, false},
		{SeverityInfo, true},
		{SeverityLow, true},
		{SeverityMedium, true},
		{SeverityHigh, true},
		{SeverityCritical, true},
		{Severity(99), false},
	}
	for _, tt := range tests {
		if got := tt.sev.IsValid(); got != tt.want {
			t.Errorf("Severity(%d).IsValid() = %v, want %v", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityGte(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b Severity
		want bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityLow, SeverityHigh, false},
		{SeverityNone, SeverityInfo, false},
	}
	for _, tt := range tests {
		if got := tt.a.Gte(tt.b); got != tt.want {
			t.Errorf("%v.Gte(%v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSeverityWeight(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 75},
		{SeverityMedium, 50},
		{SeverityLow, 25},
		{SeverityInfo, 10},
		{SeverityNone, 10},
	}
	for _, tt := range tests {
		if got := tt.sev.Weight(); got != tt.want {
			t.Errorf("Severity(%v).Weight() = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityBucketName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
		{SeverityNone, "info"},
	}
	for _, tt := range tests {
		if got := tt.sev.BucketName(); got != tt.want {
			t.Errorf("Severity(%v).BucketName() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input   string
		want    Severity
		wantErr bool
	}{
		{"info", SeverityInfo, false},
		{"LOW", SeverityLow, false},
		{" Medium ", SeverityMedium, false},
		{"high", SeverityHigh, false},
		{"critical", SeverityCritical, false},
		{"none", SeverityNone, false},
		{"", SeverityNone, false},
		{"bogus", SeverityNone, true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSeverity(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSeverityMarshalText(t *testing.T) {
	t.Parallel()
	b, err := SeverityHigh.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "high" {
		t.Fatalf("MarshalText = %q, want %q", b, "high")
	}
}

func TestSeverityUnmarshalText(t *testing.T) {
	t.Parallel()
	var s Severity
	if err := s.UnmarshalText([]byte("critical")); err != nil {
		t.Fatal(err)
	}
	if s != SeverityCritical {
		t.Fatalf("got %v, want SeverityCritical", s)
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(SeverityMedium)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"medium"` {
		t.Fatalf("MarshalJSON = %s, want %q", b, "medium")
	}
}

func TestSeverityUnmarshalJSON(t *testing.T) {
	t.Parallel()
	var s Severity
	if err := json.Unmarshal([]byte(`"low"`), &s); err != nil {
		t.Fatal(err)
	}
	if s != SeverityLow {
		t.Fatalf("got %v, want SeverityLow", s)
	}
}

// ---------------------------------------------------------------------------
// ControlType
// ---------------------------------------------------------------------------

func TestControlTypeString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ct   ControlType
		want string
	}{
		{TypeUnknown, "unknown"},
		{TypeUnsafeState, "unsafe_state"},
		{TypeUnsafeDuration, "unsafe_duration"},
		{TypeUnsafeRecurrence, "unsafe_recurrence"},
		{TypeAuthorizationBoundary, "authorization_boundary"},
		{TypeAudienceBoundary, "audience_boundary"},
		{TypeJustificationRequired, "justification_required"},
		{TypeOwnershipRequired, "ownership_required"},
		{TypeVisibilityRequired, "visibility_required"},
		{TypePrefixExposure, "prefix_exposure"},
	}
	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("ControlType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

func TestControlTypeIsValid(t *testing.T) {
	t.Parallel()
	if TypeUnknown.IsValid() {
		t.Error("TypeUnknown should not be valid")
	}
	if !TypeUnsafeState.IsValid() {
		t.Error("TypeUnsafeState should be valid")
	}
	if !TypePrefixExposure.IsValid() {
		t.Error("TypePrefixExposure should be valid")
	}
}

func TestParseControlType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input   string
		want    ControlType
		wantErr bool
	}{
		{"unsafe_state", TypeUnsafeState, false},
		{"UNSAFE_DURATION", TypeUnsafeDuration, false},
		{" unsafe_recurrence ", TypeUnsafeRecurrence, false},
		{"unknown", TypeUnknown, false},
		{"", TypeUnknown, false},
		{"nonsense", TypeUnknown, true},
	}
	for _, tt := range tests {
		got, err := ParseControlType(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseControlType(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseControlType(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestControlTypeMarshalJSON(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(TypeUnsafeState)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"unsafe_state"` {
		t.Fatalf("got %s", b)
	}
}

func TestControlTypeUnmarshalJSON(t *testing.T) {
	t.Parallel()
	var ct ControlType
	if err := json.Unmarshal([]byte(`"prefix_exposure"`), &ct); err != nil {
		t.Fatal(err)
	}
	if ct != TypePrefixExposure {
		t.Fatalf("got %v, want TypePrefixExposure", ct)
	}
}

// ---------------------------------------------------------------------------
// ControlParams
// ---------------------------------------------------------------------------

func TestControlParamsGetSet(t *testing.T) {
	t.Parallel()
	p := NewParams(map[string]any{"key1": "val1"})

	v, ok := p.Get("key1")
	if !ok || v != "val1" {
		t.Fatalf("Get(key1) = %v, %v", v, ok)
	}

	_, ok = p.Get("missing")
	if ok {
		t.Fatal("Get(missing) should return false")
	}

	p.Set("key2", 42)
	v, ok = p.Get("key2")
	if !ok || v != 42 {
		t.Fatalf("Get(key2) = %v, %v", v, ok)
	}
}

func TestControlParamsSetOnZero(t *testing.T) {
	t.Parallel()
	var p ControlParams
	if !p.IsZero() {
		t.Fatal("zero value should be zero")
	}
	p.Set("a", "b")
	if p.IsZero() {
		t.Fatal("should no longer be zero after Set")
	}
	if p.Len() != 1 {
		t.Fatalf("Len = %d, want 1", p.Len())
	}
}

func TestControlParamsHasKey(t *testing.T) {
	t.Parallel()
	p := NewParams(map[string]any{"x": 1})
	if !p.HasKey("x") {
		t.Fatal("expected HasKey(x) = true")
	}
	if p.HasKey("y") {
		t.Fatal("expected HasKey(y) = false")
	}

	var zero ControlParams
	if zero.HasKey("x") {
		t.Fatal("zero value HasKey should be false")
	}
}

func TestControlParamsGetOnZero(t *testing.T) {
	t.Parallel()
	var zero ControlParams
	_, ok := zero.Get("anything")
	if ok {
		t.Fatal("expected false from zero params")
	}
}

func TestControlParamsRaw(t *testing.T) {
	t.Parallel()
	var zero ControlParams
	if zero.Raw() != nil {
		t.Fatal("zero Raw should be nil")
	}
	p := NewParams(map[string]any{"a": 1})
	if p.Raw() == nil {
		t.Fatal("non-zero Raw should not be nil")
	}
}

func TestParamString(t *testing.T) {
	t.Parallel()
	p := NewParams(map[string]any{"s": "hello", "n": 42})
	if got := p.paramString("s"); got != "hello" {
		t.Fatalf("got %q", got)
	}
	if got := p.paramString("n"); got != "" {
		t.Fatalf("int should not match string: got %q", got)
	}
	if got := p.paramString("missing"); got != "" {
		t.Fatalf("missing should be empty: got %q", got)
	}
}

func TestParamInt(t *testing.T) {
	t.Parallel()
	p := NewParams(map[string]any{
		"int":     42,
		"int64":   int64(100),
		"float64": float64(3.14),
		"str":     "abc",
	})
	if got := p.paramInt("int"); got != 42 {
		t.Fatalf("paramInt(int) = %d", got)
	}
	if got := p.paramInt("int64"); got != 100 {
		t.Fatalf("paramInt(int64) = %d", got)
	}
	if got := p.paramInt("float64"); got != 3 {
		t.Fatalf("paramInt(float64) = %d", got)
	}
	if got := p.paramInt("str"); got != 0 {
		t.Fatalf("paramInt(str) = %d", got)
	}
	if got := p.paramInt("missing"); got != 0 {
		t.Fatalf("paramInt(missing) = %d", got)
	}

	var zero ControlParams
	if got := zero.paramInt("x"); got != 0 {
		t.Fatal("zero paramInt should be 0")
	}
}

func TestParamStringSlice(t *testing.T) {
	t.Parallel()
	p := NewParams(map[string]any{
		"str_slice": []string{"a", "b"},
		"any_slice": []any{"c", "d", 42},
		"number":    123,
	})
	got := p.paramStringSlice("str_slice")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("str_slice: %v", got)
	}
	got = p.paramStringSlice("any_slice")
	if len(got) != 2 || got[0] != "c" || got[1] != "d" {
		t.Fatalf("any_slice: %v (non-string items dropped)", got)
	}
	got = p.paramStringSlice("number")
	if got != nil {
		t.Fatalf("number should return nil: %v", got)
	}
	got = p.paramStringSlice("missing")
	if got != nil {
		t.Fatalf("missing should return nil: %v", got)
	}

	var zero ControlParams
	if zero.paramStringSlice("x") != nil {
		t.Fatal("zero paramStringSlice should be nil")
	}
}

func TestControlParamsMarshalJSON(t *testing.T) {
	t.Parallel()
	// nil map -> {}
	var zero ControlParams
	b, err := json.Marshal(zero)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}" {
		t.Fatalf("nil params JSON = %s, want {}", b)
	}

	// non-nil map
	p := NewParams(map[string]any{"k": "v"})
	b, err = json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"k":"v"}` {
		t.Fatalf("got %s", b)
	}
}

func TestControlParamsUnmarshalJSON(t *testing.T) {
	t.Parallel()
	var p ControlParams
	if err := json.Unmarshal([]byte(`{"a":1}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Len() != 1 {
		t.Fatalf("Len = %d", p.Len())
	}

	// null should clear
	if err := json.Unmarshal([]byte("null"), &p); err != nil {
		t.Fatal(err)
	}
	if !p.IsZero() {
		t.Fatal("should be zero after null")
	}
}

func TestControlParams_MarshalUnmarshal_RoundTrip_IsZero(t *testing.T) {
	t.Parallel()
	var zero ControlParams
	if !zero.IsZero() {
		t.Fatal("expected zero ControlParams initially")
	}

	b, err := json.Marshal(zero)
	if err != nil {
		t.Fatal(err)
	}

	var roundTripped ControlParams
	if err := json.Unmarshal(b, &roundTripped); err != nil {
		t.Fatal(err)
	}

	if !roundTripped.IsZero() {
		t.Fatal("expected round-tripped zero ControlParams to still be zero (IsZero() == true)")
	}
}

// ---------------------------------------------------------------------------
// ControlDefinition
// ---------------------------------------------------------------------------

func TestControlDefinitionPrepare(t *testing.T) {
	t.Parallel()
	ctl := ControlDefinition{
		Params: NewParams(map[string]any{"max_unsafe_duration": "24h"}),
	}
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("Prepare() err = %v", err)
	}
	if !ctl.prepared.Ready {
		t.Fatal("should be ready")
	}
	if ctl.prepared.MaxUnsafeDuration != 24*time.Hour {
		t.Fatalf("MaxUnsafeDuration = %v", ctl.prepared.MaxUnsafeDuration)
	}
	if !ctl.prepared.HasMaxUnsafeDuration {
		t.Fatal("HasMaxUnsafeDuration should be true")
	}

	// Idempotent
	if err := ctl.Prepare(); err != nil {
		t.Fatalf("second Prepare() err = %v", err)
	}
}

func TestControlDefinitionPrepareInvalidDuration(t *testing.T) {
	t.Parallel()
	ctl := ControlDefinition{
		Params: NewParams(map[string]any{"max_unsafe_duration": "bogus"}),
	}
	err := ctl.Prepare()
	if err == nil {
		t.Fatal("expected error for invalid duration")
	}
	// Not marked ready on error — prevents silently using zero-value duration.
	if ctl.prepared.Ready {
		t.Fatal("should not be ready after parse error")
	}
}

func TestControlDefinitionEffectiveMaxUnsafeDuration(t *testing.T) {
	t.Parallel()
	fallback := 48 * time.Hour

	// No per-control override: returns fallback
	ctl := ControlDefinition{}
	if got := ctl.EffectiveMaxUnsafeDuration(fallback); got != fallback {
		t.Fatalf("got %v, want fallback %v", got, fallback)
	}

	// Per-control override
	ctl = ControlDefinition{
		Params: NewParams(map[string]any{"max_unsafe_duration": "12h"}),
	}
	if got := ctl.EffectiveMaxUnsafeDuration(fallback); got != 12*time.Hour {
		t.Fatalf("got %v, want 12h", got)
	}
}

func TestControlDefinitionIsEvaluatable(t *testing.T) {
	t.Parallel()
	evaluatable := []ControlType{TypeUnsafeState, TypeUnsafeDuration, TypeUnsafeRecurrence, TypePrefixExposure}
	for _, ct := range evaluatable {
		ctl := ControlDefinition{Type: ct}
		if !ctl.IsEvaluatable() {
			t.Errorf("Type %v should be evaluatable", ct)
		}
	}

	notEvaluatable := []ControlType{TypeUnknown, TypeAuthorizationBoundary, TypeOwnershipRequired}
	for _, ct := range notEvaluatable {
		ctl := ControlDefinition{Type: ct}
		if ctl.IsEvaluatable() {
			t.Errorf("Type %v should not be evaluatable", ct)
		}
	}
}

func TestControlDefinitionHasCompliance(t *testing.T) {
	t.Parallel()
	ctl := ControlDefinition{
		Compliance: ComplianceMapping{"hipaa": "164.312(a)(1)", "nist": "SC-1"},
	}
	if !ctl.HasCompliance("hipaa") {
		t.Fatal("should have hipaa")
	}
	if ctl.HasCompliance("pci") {
		t.Fatal("should not have pci")
	}
}

func TestControlDefinitionMetadata(t *testing.T) {
	t.Parallel()
	ctl := ControlDefinition{
		ID:          kernel.ControlID("CTL.TEST.001"),
		Name:        "test-ctrl",
		Description: "test desc",
		Severity:    SeverityHigh,
		Compliance:  ComplianceMapping{"hipaa": "section-1"},
	}
	m := ctl.Metadata()
	if m.ID != ctl.ID || m.Name != ctl.Name || m.Severity != ctl.Severity {
		t.Fatalf("Metadata mismatch: %+v", m)
	}
}

func TestControlDefinitionsSearchByID(t *testing.T) {
	t.Parallel()
	defs := ControlDefinitions{
		{ID: kernel.ControlID("CTL.A.001")},
		{ID: kernel.ControlID("CTL.B.002")},
	}
	if got := defs.FindByID("CTL.A.001"); got == nil {
		t.Fatal("should find CTL.A.001")
	}
	if got := defs.FindByID("CTL.C.003"); got != nil {
		t.Fatal("should not find CTL.C.003")
	}
}

// ---------------------------------------------------------------------------
// Operand
// ---------------------------------------------------------------------------

func TestOperand(t *testing.T) {
	t.Parallel()
	o := Bool(true)
	if o.Raw() != true {
		t.Fatal("Bool operand")
	}

	o = Str("hello")
	if o.Raw() != "hello" {
		t.Fatal("Str operand")
	}

	o = NewOperand(42)
	if o.Raw() != 42 {
		t.Fatal("NewOperand")
	}
}

func TestOperandMarshalJSON(t *testing.T) {
	t.Parallel()
	o := Bool(true)
	b, err := o.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "true" {
		t.Fatalf("got %s", b)
	}

	var o2 Operand
	if err := o2.UnmarshalJSON([]byte(`"test"`)); err != nil {
		t.Fatal(err)
	}
	if o2.Raw() != "test" {
		t.Fatalf("got %v", o2.Raw())
	}
}

// ---------------------------------------------------------------------------
// ComplianceMapping
// ---------------------------------------------------------------------------

func TestComplianceMapping(t *testing.T) {
	t.Parallel()
	var nilMap ComplianceMapping
	if nilMap.Get("anything") != "" {
		t.Fatal("nil map Get should return empty string")
	}
	if nilMap.Has("anything") {
		t.Fatal("nil map Has should return false")
	}

	m := ComplianceMapping{"hipaa": "164.312", "nist": ""}
	if m.Get("hipaa") != "164.312" {
		t.Fatal("Get(hipaa)")
	}
	if !m.Has("nist") {
		t.Fatal("Has(nist) should be true even if value is empty")
	}
	if m.Has("pci") {
		t.Fatal("Has(pci) should be false")
	}
}

// ---------------------------------------------------------------------------
// Exposure
// ---------------------------------------------------------------------------

func TestExposureIsPublic(t *testing.T) {
	t.Parallel()
	var nilExp *Exposure
	if nilExp.IsPublic() {
		t.Fatal("nil exposure should not be public")
	}

	e := &Exposure{
		Type:           exposure.Type("public_read"),
		PrincipalScope: kernel.ScopePublic,
	}
	if !e.IsPublic() {
		t.Fatal("should be public")
	}

	e.PrincipalScope = kernel.ScopeAccount
	if e.IsPublic() {
		t.Fatal("account scope should not be public")
	}
}

func TestExposureIsValid(t *testing.T) {
	t.Parallel()
	if (&Exposure{}).IsValid() {
		t.Fatal("empty exposure should not be valid")
	}

	var nilExp *Exposure
	if nilExp.IsValid() {
		t.Fatal("nil exposure should not be valid")
	}

	e := &Exposure{
		Type:           exposure.Type("public_read"),
		PrincipalScope: kernel.ScopePublic,
	}
	if !e.IsValid() {
		t.Fatal("should be valid")
	}
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

func TestCatalog(t *testing.T) {
	t.Parallel()
	ctls := []ControlDefinition{
		{ID: kernel.ControlID("CTL.Z.001")},
		{ID: kernel.ControlID("CTL.A.001")},
		{ID: kernel.ControlID("CTL.M.001")},
	}
	cat := NewCatalog(ctls)

	if cat.Len() != 3 {
		t.Fatalf("Len = %d, want 3", cat.Len())
	}

	list := cat.List()
	if list[0].ID != "CTL.A.001" || list[1].ID != "CTL.M.001" || list[2].ID != "CTL.Z.001" {
		t.Fatalf("not sorted: %v %v %v", list[0].ID, list[1].ID, list[2].ID)
	}
}

func TestCatalogNil(t *testing.T) {
	t.Parallel()
	var cat *Catalog
	if cat.List() != nil {
		t.Fatal("nil List should return nil")
	}
	if cat.Len() != 0 {
		t.Fatal("nil Len should return 0")
	}
}

// ---------------------------------------------------------------------------
// RemediationSpec
// ---------------------------------------------------------------------------

func TestRemediationSpecActionable(t *testing.T) {
	t.Parallel()
	var nilSpec *RemediationSpec
	if nilSpec.HasAction() {
		t.Fatal("nil spec should not be actionable")
	}

	s := &RemediationSpec{}
	if s.HasAction() {
		t.Fatal("empty action should not be actionable")
	}

	s.Action = "do something"
	if !s.HasAction() {
		t.Fatal("should be actionable")
	}
}

func TestNewRemediationSpec(t *testing.T) {
	t.Parallel()
	s := NewRemediationSpec("  desc  ", "  action  ", "  example  ")
	if s.Description != "desc" {
		t.Fatalf("Description = %q", s.Description)
	}
	if s.Action != "action" {
		t.Fatalf("Action = %q", s.Action)
	}
	if s.Example != "  example  " {
		t.Fatalf("Example should not be trimmed: %q", s.Example)
	}
}

// ---------------------------------------------------------------------------
// RecurrencePolicy
// ---------------------------------------------------------------------------

func TestRecurrencePolicyEnabled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		limit, window int
		want          bool
	}{
		{0, 0, false},
		{3, 0, false},
		{0, 7, false},
		{3, 7, true},
	}
	for _, tt := range tests {
		p := RecurrencePolicy{Threshold: tt.limit, WindowDays: tt.window}
		if got := p.Enabled(); got != tt.want {
			t.Errorf("Enabled(%d,%d) = %v, want %v", tt.limit, tt.window, got, tt.want)
		}
	}
}

func TestRecurrencePolicyWindowDuration(t *testing.T) {
	t.Parallel()
	p := RecurrencePolicy{Threshold: 3, WindowDays: 7}
	if got := p.WindowDuration(); got != 7*24*time.Hour {
		t.Fatalf("WindowDuration = %v", got)
	}
}

func TestRecurrencePolicyWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	// Not enabled
	disabled := RecurrencePolicy{}
	w := disabled.Window(now)
	if !w.Start.IsZero() || !w.End.IsZero() {
		t.Fatal("disabled policy should return zero window")
	}

	// Enabled
	p := RecurrencePolicy{Threshold: 3, WindowDays: 7}
	w = p.Window(now)
	if w.End != now {
		t.Fatalf("End = %v, want %v", w.End, now)
	}
	wantStart := now.AddDate(0, 0, -7)
	if w.Start != wantStart {
		t.Fatalf("Start = %v, want %v", w.Start, wantStart)
	}
}

func TestParseRecurrencePolicy(t *testing.T) {
	t.Parallel()
	p := NewParams(map[string]any{
		"recurrence_threshold": 3,
		"window_days":          7,
	})
	rp := ParseRecurrencePolicy(p)
	if rp.Threshold != 3 || rp.WindowDays != 7 {
		t.Fatalf("got %+v", rp)
	}
}

// ---------------------------------------------------------------------------
// PrefixSet
// ---------------------------------------------------------------------------

func TestPrefixSetEmpty(t *testing.T) {
	t.Parallel()
	ps := NewPrefixSet()
	if !ps.Empty() {
		t.Fatal("should be empty")
	}

	ps = NewPrefixSet("  ", "")
	if !ps.Empty() {
		t.Fatal("whitespace-only should be empty")
	}
}

func TestPrefixSetNormalization(t *testing.T) {
	t.Parallel()
	ps := NewPrefixSet("data", "data/sub", "logs")
	prefixes := ps.Prefixes()

	// "data/sub" is redundant because "data/" contains it
	if len(prefixes) != 2 {
		t.Fatalf("expected 2 prefixes, got %d: %v", len(prefixes), prefixes)
	}
	if prefixes[0] != "data/" || prefixes[1] != "logs/" {
		t.Fatalf("unexpected: %v", prefixes)
	}
}

func TestPrefixSetOverlap(t *testing.T) {
	t.Parallel()
	allowed := NewPrefixSet("public/images")
	protected := NewPrefixSet("public/images/secret")

	conflict := allowed.Overlap(protected)
	if conflict == nil {
		t.Fatal("expected overlap")
	}

	// No overlap
	allowed = NewPrefixSet("public")
	protected = NewPrefixSet("private")
	if allowed.Overlap(protected) != nil {
		t.Fatal("should not overlap")
	}
}

// ---------------------------------------------------------------------------
// Misconfiguration
// ---------------------------------------------------------------------------

func TestMisconfigurationDisplayProperty(t *testing.T) {
	t.Parallel()
	m := Misconfiguration{Property: predicate.NewFieldPath("properties.storage.public_read")}
	if got := m.DisplayProperty(); got != "storage.public_read" {
		t.Fatalf("DisplayProperty = %q", got)
	}

	m = Misconfiguration{Property: predicate.NewFieldPath("no_prefix")}
	if got := m.DisplayProperty(); got != "no_prefix" {
		t.Fatalf("DisplayProperty = %q", got)
	}
}

func TestMisconfigurationIsMissing(t *testing.T) {
	t.Parallel()
	m := Misconfiguration{Operator: predicate.OpMissing}
	if !m.IsMissing() {
		t.Fatal("OpMissing should be missing")
	}

	m = Misconfiguration{Operator: predicate.OpEq, ActualValue: nil}
	if !m.IsMissing() {
		t.Fatal("nil ActualValue should be missing")
	}

	m = Misconfiguration{Operator: predicate.OpEq, ActualValue: false}
	if m.IsMissing() {
		t.Fatal("false ActualValue should not be missing")
	}
}

func TestMisconfigurationString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		m    Misconfiguration
		want string
	}{
		{
			"missing",
			Misconfiguration{Property: predicate.NewFieldPath("properties.x"), Operator: predicate.OpMissing},
			`property "x" is missing`,
		},
		{
			"eq",
			Misconfiguration{Property: predicate.NewFieldPath("properties.x"), Operator: predicate.OpEq, ActualValue: true},
			`property "x" has unsafe value: true`,
		},
		{
			"ne",
			Misconfiguration{Property: predicate.NewFieldPath("properties.x"), Operator: predicate.OpNe, ActualValue: "abc"},
			`property "x" value abc is unsafe`,
		},
		{
			"contains",
			Misconfiguration{Property: predicate.NewFieldPath("properties.list"), Operator: predicate.OpContains, ActualValue: "bad"},
			`property "list" contains unsafe element: bad`,
		},
		{
			"in",
			Misconfiguration{
				Property:    predicate.NewFieldPath("properties.x"),
				Operator:    predicate.OpIn,
				ActualValue: "val",
				UnsafeValue: []string{"val", "other"},
			},
			`property "x" value val is within unsafe set [val other]`,
		},
		{
			"any_match",
			Misconfiguration{Property: predicate.NewFieldPath("properties.items"), Operator: predicate.OpAnyMatch, ActualValue: []string{"x"}},
			`one or more items in "items" matched unsafe criteria`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.m.String()
			if got != tt.want {
				t.Errorf("\ngot:  %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestClassifyProperty(t *testing.T) {
	t.Parallel()
	if classifyProperty("some_via_identity_field") != CategoryIdentity {
		t.Fatal("identity suffix")
	}
	if classifyProperty("some_via_resource_field") != CategoryResource {
		t.Fatal("resource suffix")
	}
	if classifyProperty("plain_field") != CategoryUnknown {
		t.Fatal("no suffix")
	}
}

// ---------------------------------------------------------------------------
// ExceptionConfig
// ---------------------------------------------------------------------------

func TestExceptionRuleValidate(t *testing.T) {
	t.Parallel()
	r := ExceptionRule{}
	if r.Validate() == nil {
		t.Fatal("empty rule should fail validation")
	}

	r = ExceptionRule{ControlID: "CTL.TEST.001"}
	if r.Validate() == nil {
		t.Fatal("missing asset_id should fail")
	}

	r = ExceptionRule{ControlID: "CTL.TEST.001", AssetID: "bucket-a"}
	if r.Validate() != nil {
		t.Fatal("valid rule should pass")
	}
}

func TestExpiryDate(t *testing.T) {
	t.Parallel()
	d, err := ParseExpiryDate("")
	if err != nil || !d.IsZero() {
		t.Fatal("empty string should return zero")
	}

	d, err = ParseExpiryDate("2026-01-15")
	if err != nil {
		t.Fatal(err)
	}
	if d.IsZero() {
		t.Fatal("should not be zero")
	}
	if d.String() != "2026-01-15" {
		t.Fatalf("String = %q", d.String())
	}

	// Zero value
	var zero ExpiryDate
	if zero.String() != "never" {
		t.Fatalf("zero String = %q", zero.String())
	}

	_, err = ParseExpiryDate("not-a-date")
	if err == nil {
		t.Fatal("should error on invalid date")
	}
}

func TestExpiryDateIsExpired(t *testing.T) {
	t.Parallel()
	d, _ := ParseExpiryDate("2026-01-15")
	now := time.Date(2026, 1, 15, 23, 59, 59, 0, time.UTC)
	if d.IsExpired(now) {
		t.Fatal("should still be active on the same day")
	}

	now = time.Date(2026, 1, 16, 0, 0, 0, 0, time.UTC)
	if !d.IsExpired(now) {
		t.Fatal("should be expired at start of next day")
	}

	// Zero date never expires
	var zero ExpiryDate
	if zero.IsExpired(time.Now()) {
		t.Fatal("zero date should never expire")
	}
}

func TestExceptionConfigShouldExcept(t *testing.T) {
	t.Parallel()
	rules := []ExceptionRule{
		{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-a", Reason: "known safe"},
		{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-*", Reason: "glob match"},
	}
	cfg := NewExceptionConfig(rules)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Exact match
	r := cfg.ShouldExcept("CTL.S3.PUBLIC.001", "bucket-a", now)
	if r == nil {
		t.Fatal("should match exact")
	}
	if r.Reason != "known safe" {
		t.Fatalf("Reason = %q", r.Reason)
	}

	// Glob match
	r = cfg.ShouldExcept("CTL.S3.PUBLIC.001", "bucket-xyz", now)
	if r == nil {
		t.Fatal("should match glob")
	}

	// No match
	r = cfg.ShouldExcept("CTL.OTHER.001", "bucket-a", now)
	if r != nil {
		t.Fatal("should not match different control")
	}

	// Nil config
	var nilCfg *ExceptionConfig
	if nilCfg.ShouldExcept("CTL.S3.PUBLIC.001", "bucket-a", now) != nil {
		t.Fatal("nil config should return nil")
	}
}

// ---------------------------------------------------------------------------
// ExemptionConfig
// ---------------------------------------------------------------------------

func TestExemptionConfigShouldExempt(t *testing.T) {
	t.Parallel()
	cfg := NewExemptionConfig("v1", []ExemptionRule{
		{Pattern: "bucket-static", Reason: "static site"},
		{Pattern: "bucket-*-temp", Reason: "temporary"},
	})

	// Exact match
	r := cfg.ShouldExempt("bucket-static")
	if r == nil || r.Reason != "static site" {
		t.Fatal("expected exact match")
	}

	// Glob match
	r = cfg.ShouldExempt("bucket-123-temp")
	if r == nil || r.Reason != "temporary" {
		t.Fatal("expected glob match")
	}

	// No match
	r = cfg.ShouldExempt("bucket-other")
	if r != nil {
		t.Fatal("should not match")
	}

	// Nil config
	var nilCfg *ExemptionConfig
	if nilCfg.ShouldExempt("anything") != nil {
		t.Fatal("nil config should return nil")
	}
}

// ---------------------------------------------------------------------------
// Glob matching
// ---------------------------------------------------------------------------

func TestGlobMatch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"bucket-*", "bucket-foo", true},
		{"bucket-*", "other-foo", false},
		{"*-suffix", "prefix-suffix", true},
		{"*-suffix", "prefix-other", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
		{"exact", "exact", true},
		{"exact", "other", false},
	}
	for _, tt := range tests {
		if got := globMatch(tt.pattern, tt.s); got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestMatchPattern(t *testing.T) {
	t.Parallel()
	if !matchPattern("exact", "exact") {
		t.Fatal("exact match failed")
	}
	if matchPattern("exact", "other") {
		t.Fatal("exact non-match")
	}
	if !matchPattern("prefix-*", "prefix-foo") {
		t.Fatal("glob match failed")
	}
}

// ---------------------------------------------------------------------------
// Fields: resolvePropertyValue and getNestedValue
// ---------------------------------------------------------------------------

func TestResolvePropertyValue(t *testing.T) {
	t.Parallel()
	props := map[string]any{
		"storage": map[string]any{
			"encryption": true,
		},
	}

	// Direct path
	val, ok := resolvePropertyValue(props, []string{"storage", "encryption"})
	if !ok || val != true {
		t.Fatalf("direct path: %v %v", val, ok)
	}

	// With "properties" prefix
	val, ok = resolvePropertyValue(props, []string{"properties", "storage", "encryption"})
	if !ok || val != true {
		t.Fatalf("properties prefix: %v %v", val, ok)
	}

	// Just "properties" returns entire map
	_, ok = resolvePropertyValue(props, []string{"properties"})
	if !ok {
		t.Fatal("should return entire props")
	}

	// Empty path
	_, ok = resolvePropertyValue(props, nil)
	if ok {
		t.Fatal("empty path should return false")
	}

	// Missing key
	_, ok = resolvePropertyValue(props, []string{"nonexistent"})
	if ok {
		t.Fatal("missing key should return false")
	}
}

func TestGetNestedValue(t *testing.T) {
	t.Parallel()
	data := map[string]any{
		"level1": map[string]any{
			"level2": "value",
		},
		"str_map": map[string]string{
			"key": "val",
		},
	}

	// Nested map[string]any
	val, ok := getNestedValue(data, []string{"level1", "level2"})
	if !ok || val != "value" {
		t.Fatalf("nested: %v %v", val, ok)
	}

	// map[string]string
	val, ok = getNestedValue(data, []string{"str_map", "key"})
	if !ok || val != "val" {
		t.Fatalf("str_map: %v %v", val, ok)
	}

	// nil current
	_, ok = getNestedValue(nil, []string{"x"})
	if ok {
		t.Fatal("nil should fail")
	}

	// Wrong type at leaf
	_, ok = getNestedValue(data, []string{"level1", "level2", "deeper"})
	if ok {
		t.Fatal("should fail when traversing a string")
	}

	// Empty parts
	_, ok = getNestedValue(data, nil)
	if !ok {
		t.Fatal("empty parts should return data itself")
	}

	// map[any]any
	yamlLike := map[any]any{"k": "v"}
	val, ok = getNestedValue(yamlLike, []string{"k"})
	if !ok || val != "v" {
		t.Fatalf("map[any]any: %v %v", val, ok)
	}
}

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

func TestPredicateWalk(t *testing.T) {
	t.Parallel()
	pred := UnsafePredicate{
		Any: []PredicateRule{
			{Field: predicate.NewFieldPath("field1")},
			{
				All: []PredicateRule{
					{Field: predicate.NewFieldPath("field2")},
				},
			},
		},
	}

	var visited []string
	pred.Walk(func(r PredicateRule) {
		if !r.Field.IsZero() {
			visited = append(visited, r.Field.String())
		}
	})

	if len(visited) != 2 || visited[0] != "field1" || visited[1] != "field2" {
		t.Fatalf("visited = %v", visited)
	}
}

// ---------------------------------------------------------------------------
// MissingParamReferences
// ---------------------------------------------------------------------------

func TestMissingParamReferences(t *testing.T) {
	t.Parallel()
	pred := UnsafePredicate{
		Any: []PredicateRule{
			{ValueFromParam: predicate.ParamRef("defined_param")},
			{ValueFromParam: predicate.ParamRef("missing_param")},
		},
	}
	params := NewParams(map[string]any{"defined_param": "value"})
	missing := pred.MissingParamReferences(params)
	if len(missing) != 1 || missing[0] != "missing_param" {
		t.Fatalf("missing = %v", missing)
	}

	// No missing
	params.Set("missing_param", "val2")
	missing = pred.MissingParamReferences(params)
	if len(missing) != 0 {
		t.Fatalf("expected none, got %v", missing)
	}
}

// ---------------------------------------------------------------------------
// NewAssetEvalContext
// ---------------------------------------------------------------------------

func TestNewAssetEvalContext(t *testing.T) {
	t.Parallel()
	a := asset.Asset{
		ID:         asset.ID("bucket-1"),
		Properties: map[string]any{"k": "v"},
	}
	params := NewParams(map[string]any{"p": 1})
	ctx := NewAssetEvalContext(a, params, nil)
	if ctx.PropertyMap() == nil {
		t.Fatal("Properties should not be nil")
	}
	if _, ok := ctx.GetProperty("k"); !ok {
		t.Fatal("should have properties from asset")
	}
}
