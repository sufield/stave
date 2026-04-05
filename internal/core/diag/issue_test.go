package diag

import "testing"

func TestNew_DefaultsToError(t *testing.T) {
	b := New(RuleSchemaViolation)
	finding := b.Build()
	if finding.Severity != SeverityError {
		t.Fatalf("default severity=%q, want %q", finding.Severity, SeverityError)
	}
	if finding.RuleID != RuleSchemaViolation {
		t.Fatalf("rule_id=%q, want %q", finding.RuleID, RuleSchemaViolation)
	}
}

func TestBuilder_Warning(t *testing.T) {
	finding := New(RuleNoSnapshots).Warning().Build()
	if finding.Severity != SeverityWarn {
		t.Fatalf("severity=%q, want %q", finding.Severity, SeverityWarn)
	}
}

func TestBuilder_Msg(t *testing.T) {
	finding := New(RuleNoControls).Msg("no controls found").Build()
	if finding.Message != "no controls found" {
		t.Fatalf("message=%q, want %q", finding.Message, "no controls found")
	}
}

func TestBuilder_Action(t *testing.T) {
	finding := New(RuleNoControls).Action("add controls").Build()
	if finding.Action != "add controls" {
		t.Fatalf("action=%q, want %q", finding.Action, "add controls")
	}
}

func TestBuilder_Command(t *testing.T) {
	finding := New(RuleNoControls).Command("stave init").Build()
	if finding.Command != "stave init" {
		t.Fatalf("command=%q, want %q", finding.Command, "stave init")
	}
}

func TestBuilder_With(t *testing.T) {
	finding := New(RuleSchemaViolation).With("path", "/foo").Build()
	v, ok := finding.Resource.Get("path")
	if !ok || v != "/foo" {
		t.Fatalf("resource path=%q ok=%v, want /foo true", v, ok)
	}
}

func TestBuilder_WithMap(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2"}
	finding := New(RuleSchemaViolation).WithMap(m).Build()
	for k, want := range m {
		got, ok := finding.Resource.Get(k)
		if !ok || got != want {
			t.Fatalf("resource[%q]=%q ok=%v, want %q", k, got, ok, want)
		}
	}
}

func TestBuilder_WithSensitive(t *testing.T) {
	finding := New(RuleSchemaViolation).WithSensitive("secret", "hunter2").Build()
	raw, ok := finding.Resource.Get("secret")
	if !ok || raw != "hunter2" {
		t.Fatalf("raw resource secret=%q ok=%v", raw, ok)
	}
	// Sanitized access should mask the value.
	sanitized := finding.Resource.Sanitized("secret")
	if sanitized == "hunter2" {
		t.Fatal("sanitized should not return raw sensitive value")
	}
}

func TestBuilder_Build_ClonesResource(t *testing.T) {
	b := New(RuleSchemaViolation).With("key", "val1")
	finding1 := b.Build()

	// Mutate builder after first build.
	b.With("key", "val2")
	finding2 := b.Build()

	v1, _ := finding1.Resource.Get("key")
	v2, _ := finding2.Resource.Get("key")
	if v1 == v2 {
		t.Fatal("Build should clone resource; mutations should not propagate")
	}
	if v1 != "val1" {
		t.Fatalf("finding1 resource key=%q, want val1", v1)
	}
	if v2 != "val2" {
		t.Fatalf("finding2 resource key=%q, want val2", v2)
	}
}

func TestBuilder_Fluent(t *testing.T) {
	finding := New(RuleControlLoadFailed).
		Error().
		Msg("load failed").
		Action("fix the file").
		Command("stave validate").
		With("file", "test.yaml").
		Build()

	if finding.RuleID != RuleControlLoadFailed {
		t.Fatalf("rule_id=%q", finding.RuleID)
	}
	if finding.Severity != SeverityError {
		t.Fatalf("severity=%q", finding.Severity)
	}
	if finding.Message != "load failed" {
		t.Fatalf("msg=%q", finding.Message)
	}
	if finding.Action != "fix the file" {
		t.Fatalf("action=%q", finding.Action)
	}
	if finding.Command != "stave validate" {
		t.Fatalf("command=%q", finding.Command)
	}
	f, _ := finding.Resource.Get("file")
	if f != "test.yaml" {
		t.Fatalf("resource file=%q", f)
	}
}
