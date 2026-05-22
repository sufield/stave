package config

import (
	"testing"
)

func noEnv(string) string { return "" }

func newTestEvaluator(proj *WorkspacePolicy, user *OperatorSettings) *GovernanceResolver {
	e := NewResolver(proj, "/proj/stave.yaml", user, "/home/.config/stave/config.yaml")
	e.Getenv = noEnv
	return e
}

func TestResolveMaxUnsafeDuration_Layers(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveMaxUnsafeDuration()
		if v.Value != DefaultMaxUnsafeDuration {
			t.Errorf("Value = %q, want %q", v.Value, DefaultMaxUnsafeDuration)
		}
		if v.Layer != LayerDefault {
			t.Errorf("Layer = %d, want LayerDefault", v.Layer)
		}
	})

	t.Run("user config", func(t *testing.T) {
		e := newTestEvaluator(nil, &OperatorSettings{MaxUnsafe: "24h"})
		v := e.ResolveMaxUnsafeDuration()
		if v.Value != "24h" {
			t.Errorf("Value = %q, want 24h", v.Value)
		}
		if v.Layer != LayerUserConfig {
			t.Errorf("Layer = %d, want LayerUserConfig", v.Layer)
		}
	})

	t.Run("project overrides user", func(t *testing.T) {
		e := newTestEvaluator(
			&WorkspacePolicy{MaxUnsafe: "48h"},
			&OperatorSettings{MaxUnsafe: "24h"},
		)
		v := e.ResolveMaxUnsafeDuration()
		if v.Value != "48h" {
			t.Errorf("Value = %q, want 48h", v.Value)
		}
		if v.Layer != LayerProjectConfig {
			t.Errorf("Layer = %d, want LayerProjectConfig", v.Layer)
		}
	})

	t.Run("env overrides project", func(t *testing.T) {
		e := newTestEvaluator(
			&WorkspacePolicy{MaxUnsafe: "48h"},
			nil,
		)
		e.Getenv = func(key string) string {
			if key == "STAVE_MAX_UNSAFE" {
				return "12h"
			}
			return ""
		}
		v := e.ResolveMaxUnsafeDuration()
		if v.Value != "12h" {
			t.Errorf("Value = %q, want 12h", v.Value)
		}
		if v.Layer != LayerEnvironment {
			t.Errorf("Layer = %d, want LayerEnvironment", v.Layer)
		}
	})
}

func TestResolveCIFailurePolicy(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveCIFailurePolicy()
		if v.Value != string(GateStrict) {
			t.Errorf("Value = %q, want %q", v.Value, GateStrict)
		}
	})

	t.Run("project", func(t *testing.T) {
		e := newTestEvaluator(&WorkspacePolicy{CIFailurePolicy: "fail_on_new_violation"}, nil)
		v := e.ResolveCIFailurePolicy()
		if v.Value != "fail_on_new_violation" {
			t.Errorf("Value = %q, want fail_on_new_violation", v.Value)
		}
	})
}

func TestResolveCLIOutput(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveCLIOutput()
		if v.Value != "text" {
			t.Errorf("Value = %q, want text", v.Value)
		}
	})

	t.Run("user json", func(t *testing.T) {
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{Output: "JSON"}})
		v := e.ResolveCLIOutput()
		if v.Value != "json" {
			t.Errorf("Value = %q, want json", v.Value)
		}
	})

	t.Run("user invalid falls to default", func(t *testing.T) {
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{Output: "xml"}})
		v := e.ResolveCLIOutput()
		if v.Value != "text" {
			t.Errorf("Value = %q, want text (invalid falls back)", v.Value)
		}
	})
}

func TestResolveCLIQuiet(t *testing.T) {
	t.Run("default false", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveCLIQuiet()
		if v.Value != false {
			t.Error("expected false by default")
		}
	})

	t.Run("user true", func(t *testing.T) {
		val := true
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{Quiet: &val}})
		v := e.ResolveCLIQuiet()
		if v.Value != true {
			t.Error("expected true from user config")
		}
	})
}

func TestResolveCLISanitize(t *testing.T) {
	t.Run("default false", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		if e.Sanitize() {
			t.Error("expected false by default")
		}
	})

	t.Run("user true", func(t *testing.T) {
		val := true
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{Sanitize: &val}})
		if !e.Sanitize() {
			t.Error("expected true from user config")
		}
	})
}

func TestResolveCLIPathMode(t *testing.T) {
	t.Run("default base", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		if e.PathMode() != "base" {
			t.Errorf("PathMode = %q, want base", e.PathMode())
		}
	})

	t.Run("user full", func(t *testing.T) {
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{PathMode: "Full"}})
		if e.PathMode() != "full" {
			t.Errorf("PathMode = %q, want full", e.PathMode())
		}
	})

	t.Run("user invalid falls to default", func(t *testing.T) {
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{PathMode: "invalid"}})
		if e.PathMode() != "base" {
			t.Errorf("PathMode = %q, want base", e.PathMode())
		}
	})
}

func TestResolveCLIAllowUnknownInput(t *testing.T) {
	t.Run("default false", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		if e.AllowUnknownInput() {
			t.Error("expected false by default")
		}
	})

	t.Run("user true", func(t *testing.T) {
		val := true
		e := newTestEvaluator(nil, &OperatorSettings{CLIDefaults: OperatorCLIConfig{AllowUnknownInput: &val}})
		if !e.AllowUnknownInput() {
			t.Error("expected true from user config")
		}
	})
}

func TestValueAccessors(t *testing.T) {
	e := newTestEvaluator(&WorkspacePolicy{
		MaxUnsafe:       "72h",
		CIFailurePolicy: "fail_on_new_violation",
	}, nil)

	if got := e.MaxUnsafeDuration(); got != "72h" {
		t.Errorf("MaxUnsafeDuration() = %q, want 72h", got)
	}

	if got := e.CIFailurePolicy(); got != GateRegression {
		t.Errorf("CIFailurePolicy() = %q, want %q", got, GateRegression)
	}

	if got := e.Quiet(); got != false {
		t.Error("Quiet() should be false")
	}
}

func TestWithPolicy(t *testing.T) {
	orig := newTestEvaluator(&WorkspacePolicy{MaxUnsafe: "24h"}, &OperatorSettings{MaxUnsafe: "48h"})
	updated := orig.WithPolicy(&WorkspacePolicy{MaxUnsafe: "72h"}, "/other/stave.yaml")

	if updated.MaxUnsafeDuration() != "72h" {
		t.Errorf("updated MaxUnsafe = %q, want 72h", updated.MaxUnsafeDuration())
	}

	// Original should be unchanged
	if orig.MaxUnsafeDuration() != "24h" {
		t.Errorf("original MaxUnsafe = %q, want 24h", orig.MaxUnsafeDuration())
	}

	// Settings should be inherited
	if updated.Settings != orig.Settings {
		t.Error("WithPolicy should preserve settings config")
	}
}

func TestValueString(t *testing.T) {
	v := PolicyValue[string]{Value: "168h"}
	if v.String() != "168h" {
		t.Errorf("String() = %q, want 168h", v.String())
	}

	vb := PolicyValue[bool]{Value: true}
	if vb.String() != "true" {
		t.Errorf("bool String() = %q, want true", vb.String())
	}
}
