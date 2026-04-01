package config

import (
	"testing"

	"github.com/sufield/stave/internal/core/retention"
)

func noEnv(string) string { return "" }

func newTestEvaluator(proj *ProjectConfig, user *UserConfig) *Evaluator {
	e := NewEvaluator(proj, "/proj/stave.yaml", user, "/home/.config/stave/config.yaml")
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
		e := newTestEvaluator(nil, &UserConfig{MaxUnsafe: "24h"})
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
			&ProjectConfig{MaxUnsafe: "48h"},
			&UserConfig{MaxUnsafe: "24h"},
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
			&ProjectConfig{MaxUnsafe: "48h"},
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

func TestResolveRetentionTier(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveRetentionTier()
		if v.Value != DefaultRetentionTier {
			t.Errorf("Value = %q, want %q", v.Value, DefaultRetentionTier)
		}
	})

	t.Run("project config normalizes", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{RetentionTier: "  HOT  "}, nil)
		v := e.ResolveRetentionTier()
		if v.Value != "hot" {
			t.Errorf("Value = %q, want hot", v.Value)
		}
	})

	t.Run("env override", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		e.Getenv = func(key string) string {
			if key == "STAVE_RETENTION_TIER" {
				return "COLD"
			}
			return ""
		}
		v := e.ResolveRetentionTier()
		if v.Value != "cold" {
			t.Errorf("Value = %q, want cold", v.Value)
		}
	})
}

func TestResolveSnapshotRetention(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveSnapshotRetention("critical")
		if v.Value != DefaultSnapshotRetention {
			t.Errorf("Value = %q, want %q", v.Value, DefaultSnapshotRetention)
		}
	})

	t.Run("project tier-specific", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{
			RetentionTiers: map[string]retention.Tier{
				"hot": {OlderThan: "7d"},
			},
		}, nil)
		v := e.ResolveSnapshotRetention("hot")
		if v.Value != "7d" {
			t.Errorf("Value = %q, want 7d", v.Value)
		}
	})

	t.Run("project fallback to top-level", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{
			SnapshotRetention: "14d",
		}, nil)
		v := e.ResolveSnapshotRetention("unknown")
		if v.Value != "14d" {
			t.Errorf("Value = %q, want 14d", v.Value)
		}
	})

	t.Run("user config", func(t *testing.T) {
		e := newTestEvaluator(nil, &UserConfig{SnapshotRetention: "60d"})
		v := e.ResolveSnapshotRetention("any")
		if v.Value != "60d" {
			t.Errorf("Value = %q, want 60d", v.Value)
		}
	})

	t.Run("env override", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{SnapshotRetention: "14d"}, nil)
		e.Getenv = func(key string) string {
			if key == "STAVE_SNAPSHOT_RETENTION" {
				return "3d"
			}
			return ""
		}
		v := e.ResolveSnapshotRetention("any")
		if v.Value != "3d" {
			t.Errorf("Value = %q, want 3d", v.Value)
		}
	})
}

func TestResolveCIFailurePolicy(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		v := e.ResolveCIFailurePolicy()
		if v.Value != string(GatePolicyAny) {
			t.Errorf("Value = %q, want %q", v.Value, GatePolicyAny)
		}
	})

	t.Run("project", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{CIFailurePolicy: "fail_on_new_violation"}, nil)
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
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{Output: "JSON"}})
		v := e.ResolveCLIOutput()
		if v.Value != "json" {
			t.Errorf("Value = %q, want json", v.Value)
		}
	})

	t.Run("user invalid falls to default", func(t *testing.T) {
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{Output: "xml"}})
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
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{Quiet: &val}})
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
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{Sanitize: &val}})
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
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{PathMode: "Full"}})
		if e.PathMode() != "full" {
			t.Errorf("PathMode = %q, want full", e.PathMode())
		}
	})

	t.Run("user invalid falls to default", func(t *testing.T) {
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{PathMode: "invalid"}})
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
		e := newTestEvaluator(nil, &UserConfig{CLIDefaults: UserCLIConfig{AllowUnknownInput: &val}})
		if !e.AllowUnknownInput() {
			t.Error("expected true from user config")
		}
	})
}

func TestValueAccessors(t *testing.T) {
	e := newTestEvaluator(&ProjectConfig{
		MaxUnsafe:       "72h",
		CIFailurePolicy: "fail_on_new_violation",
	}, nil)

	if got := e.MaxUnsafeDuration(); got != "72h" {
		t.Errorf("MaxUnsafeDuration() = %q, want 72h", got)
	}

	if got := e.CIFailurePolicy(); got != GatePolicyNew {
		t.Errorf("CIFailurePolicy() = %q, want %q", got, GatePolicyNew)
	}

	if got := e.RetentionTier(); got != DefaultRetentionTier {
		t.Errorf("RetentionTier() = %q, want %q", got, DefaultRetentionTier)
	}

	if got := e.SnapshotRetention(); got != DefaultSnapshotRetention {
		t.Errorf("SnapshotRetention() = %q, want %q", got, DefaultSnapshotRetention)
	}

	if got := e.Quiet(); got != false {
		t.Error("Quiet() should be false")
	}
}

func TestHasConfiguredTier(t *testing.T) {
	t.Run("nil project", func(t *testing.T) {
		e := newTestEvaluator(nil, nil)
		if e.HasConfiguredTier("hot") {
			t.Error("nil project should not have tier")
		}
	})

	t.Run("empty tiers", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{}, nil)
		if e.HasConfiguredTier("hot") {
			t.Error("empty tiers should not have tier")
		}
	})

	t.Run("tier exists", func(t *testing.T) {
		e := newTestEvaluator(&ProjectConfig{
			RetentionTiers: map[string]retention.Tier{
				"hot": {OlderThan: "7d"},
			},
		}, nil)
		if !e.HasConfiguredTier("hot") {
			t.Error("expected hot tier to exist")
		}
		if !e.HasConfiguredTier("HOT") {
			t.Error("expected case-insensitive match")
		}
		if e.HasConfiguredTier("cold") {
			t.Error("cold tier should not exist")
		}
	})
}

func TestWithProject(t *testing.T) {
	orig := newTestEvaluator(&ProjectConfig{MaxUnsafe: "24h"}, &UserConfig{MaxUnsafe: "48h"})
	updated := orig.WithProject(&ProjectConfig{MaxUnsafe: "72h"}, "/other/stave.yaml")

	if updated.MaxUnsafeDuration() != "72h" {
		t.Errorf("updated MaxUnsafe = %q, want 72h", updated.MaxUnsafeDuration())
	}

	// Original should be unchanged
	if orig.MaxUnsafeDuration() != "24h" {
		t.Errorf("original MaxUnsafe = %q, want 24h", orig.MaxUnsafeDuration())
	}

	// User config should be inherited
	if updated.User != orig.User {
		t.Error("WithProject should preserve user config")
	}
}

func TestValueString(t *testing.T) {
	v := Value[string]{Value: "168h"}
	if v.String() != "168h" {
		t.Errorf("String() = %q, want 168h", v.String())
	}

	vb := Value[bool]{Value: true}
	if vb.String() != "true" {
		t.Errorf("bool String() = %q, want true", vb.String())
	}
}
