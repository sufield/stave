package diag

import "testing"

func TestNew_DefaultsToError(t *testing.T) {
	b := New(CodeSchemaViolation)
	issue := b.Build()
	if issue.Signal != SignalError {
		t.Fatalf("default signal=%q, want %q", issue.Signal, SignalError)
	}
	if issue.Code != CodeSchemaViolation {
		t.Fatalf("code=%q, want %q", issue.Code, CodeSchemaViolation)
	}
}

func TestBuilder_Warning(t *testing.T) {
	issue := New(CodeNoSnapshots).Warning().Build()
	if issue.Signal != SignalWarn {
		t.Fatalf("signal=%q, want %q", issue.Signal, SignalWarn)
	}
}

func TestBuilder_Msg(t *testing.T) {
	issue := New(CodeNoControls).Msg("no controls found").Build()
	if issue.Message != "no controls found" {
		t.Fatalf("message=%q, want %q", issue.Message, "no controls found")
	}
}

func TestBuilder_Action(t *testing.T) {
	issue := New(CodeNoControls).Action("add controls").Build()
	if issue.Action != "add controls" {
		t.Fatalf("action=%q, want %q", issue.Action, "add controls")
	}
}

func TestBuilder_Command(t *testing.T) {
	issue := New(CodeNoControls).Command("stave init").Build()
	if issue.Command != "stave init" {
		t.Fatalf("command=%q, want %q", issue.Command, "stave init")
	}
}

func TestBuilder_With(t *testing.T) {
	issue := New(CodeSchemaViolation).With("path", "/foo").Build()
	v, ok := issue.Evidence.Get("path")
	if !ok || v != "/foo" {
		t.Fatalf("evidence path=%q ok=%v, want /foo true", v, ok)
	}
}

func TestBuilder_WithMap(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2"}
	issue := New(CodeSchemaViolation).WithMap(m).Build()
	for k, want := range m {
		got, ok := issue.Evidence.Get(k)
		if !ok || got != want {
			t.Fatalf("evidence[%q]=%q ok=%v, want %q", k, got, ok, want)
		}
	}
}

func TestBuilder_WithSensitive(t *testing.T) {
	issue := New(CodeSchemaViolation).WithSensitive("secret", "hunter2").Build()
	raw, ok := issue.Evidence.Get("secret")
	if !ok || raw != "hunter2" {
		t.Fatalf("raw evidence secret=%q ok=%v", raw, ok)
	}
	// Sanitized access should mask the value.
	sanitized := issue.Evidence.Sanitized("secret")
	if sanitized == "hunter2" {
		t.Fatal("sanitized should not return raw sensitive value")
	}
}

func TestBuilder_Build_ClonesEvidence(t *testing.T) {
	b := New(CodeSchemaViolation).With("key", "val1")
	issue1 := b.Build()

	// Mutate builder after first build.
	b.With("key", "val2")
	issue2 := b.Build()

	v1, _ := issue1.Evidence.Get("key")
	v2, _ := issue2.Evidence.Get("key")
	if v1 == v2 {
		t.Fatal("Build should clone evidence; mutations should not propagate")
	}
	if v1 != "val1" {
		t.Fatalf("issue1 evidence key=%q, want val1", v1)
	}
	if v2 != "val2" {
		t.Fatalf("issue2 evidence key=%q, want val2", v2)
	}
}

func TestBuilder_Fluent(t *testing.T) {
	issue := New(CodeControlLoadFailed).
		Error().
		Msg("load failed").
		Action("fix the file").
		Command("stave validate").
		With("file", "test.yaml").
		Build()

	if issue.Code != CodeControlLoadFailed {
		t.Fatalf("code=%q", issue.Code)
	}
	if issue.Signal != SignalError {
		t.Fatalf("signal=%q", issue.Signal)
	}
	if issue.Message != "load failed" {
		t.Fatalf("msg=%q", issue.Message)
	}
	if issue.Action != "fix the file" {
		t.Fatalf("action=%q", issue.Action)
	}
	if issue.Command != "stave validate" {
		t.Fatalf("command=%q", issue.Command)
	}
	f, _ := issue.Evidence.Get("file")
	if f != "test.yaml" {
		t.Fatalf("evidence file=%q", f)
	}
}
