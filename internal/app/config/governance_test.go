package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/retention"
)

func TestParseEnforcementGate(t *testing.T) {
	tests := []struct {
		input   string
		want    EnforcementGate
		wantErr bool
	}{
		{"fail_on_any_violation", GateStrict, false},
		{"fail_on_new_violation", GateRegression, false},
		{"fail_on_overdue_upcoming", GateSLA, false},
		{"FAIL_ON_ANY_VIOLATION", GateStrict, false},
		{"  fail_on_new_violation  ", GateRegression, false},
		{"invalid", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseEnforcementGate(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseEnforcementGate(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIdentifySetting_TopLevel(t *testing.T) {
	// GovernanceSettings should include max_unsafe, snapshot_retention, etc.
	pk, err := IdentifySetting("max_unsafe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.Attribute != "max_unsafe" {
		t.Errorf("TopLevel = %q, want max_unsafe", pk.Attribute)
	}
	if pk.TierName != "" {
		t.Error("TierName should be empty for top-level key")
	}
}

func TestIdentifySetting_TierKey(t *testing.T) {
	pk, err := IdentifySetting("snapshot_retention_tiers.hot.older_than")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.TierName != "hot" {
		t.Errorf("TierName = %q, want hot", pk.TierName)
	}
	if pk.Property != "older_than" {
		t.Errorf("SubField = %q, want older_than", pk.Property)
	}
}

func TestIdentifySetting_TierKeyNoSubField(t *testing.T) {
	pk, err := IdentifySetting("snapshot_retention_tiers.hot")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.TierName != "hot" {
		t.Errorf("TierName = %q, want hot", pk.TierName)
	}
	if pk.Property != "" {
		t.Errorf("SubField = %q, want empty", pk.Property)
	}
}

func TestIdentifySetting_TierKeyNormalized(t *testing.T) {
	pk, err := IdentifySetting("snapshot_retention_tiers.HOT.keep_min")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk.TierName != "hot" {
		t.Errorf("TierName = %q, want hot (normalized)", pk.TierName)
	}
}

func TestIdentifySetting_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"unknown key", "unknown_key"},
		{"empty tier name", "snapshot_retention_tiers."},
		{"bad tier sub-field", "snapshot_retention_tiers.hot.bad_field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := IdentifySetting(tt.input)
			if err == nil {
				t.Errorf("expected error for %q", tt.input)
			}
		})
	}
}

func TestGetAttribute(t *testing.T) {
	cfg := &WorkspacePolicy{
		MaxUnsafe:       "168h",
		CIFailurePolicy: "fail_on_any_violation",
	}

	t.Run("existing key", func(t *testing.T) {
		v, ok := GetAttribute(cfg, "max_unsafe")
		if !ok {
			t.Fatal("expected ok=true for max_unsafe")
		}
		if v != "168h" {
			t.Errorf("Value = %q, want 168h", v)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		_, ok := GetAttribute(cfg, "nonexistent")
		if ok {
			t.Error("expected ok=false for nonexistent key")
		}
	})

	t.Run("empty value", func(t *testing.T) {
		v, ok := GetAttribute(cfg, "snapshot_retention")
		if !ok {
			t.Fatal("expected ok=true for snapshot_retention")
		}
		if v != "" {
			t.Errorf("Value = %q, want empty", v)
		}
	})
}

func TestUpdateAttribute(t *testing.T) {
	t.Run("set string", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		if err := UpdateAttribute(cfg, "max_unsafe", "24h"); err != nil {
			t.Fatalf("UpdateAttribute() error: %v", err)
		}
		if cfg.MaxUnsafe != "24h" {
			t.Errorf("MaxUnsafe = %q, want 24h", cfg.MaxUnsafe)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := UpdateAttribute(cfg, "nonexistent", "value")
		if err == nil {
			t.Fatal("expected error for unknown key")
		}
	})

	t.Run("invalid duration", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := UpdateAttribute(cfg, "max_unsafe", "not-a-duration")
		if err == nil {
			t.Fatal("expected error for invalid duration")
		}
		// Should revert on validation failure
		if cfg.MaxUnsafe != "" {
			t.Errorf("MaxUnsafe = %q, want empty (reverted)", cfg.MaxUnsafe)
		}
	})

	t.Run("valid ci_failure_policy", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		if err := UpdateAttribute(cfg, "ci_failure_policy", "fail_on_new_violation"); err != nil {
			t.Fatalf("error: %v", err)
		}
		if cfg.CIFailurePolicy != "fail_on_new_violation" {
			t.Errorf("CIFailurePolicy = %q", cfg.CIFailurePolicy)
		}
	})

	t.Run("invalid ci_failure_policy", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := UpdateAttribute(cfg, "ci_failure_policy", "invalid_policy")
		if err == nil {
			t.Fatal("expected error for invalid policy")
		}
	})

	t.Run("valid capture_cadence", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		if err := UpdateAttribute(cfg, "capture_cadence", "daily"); err != nil {
			t.Fatalf("error: %v", err)
		}
		if cfg.CaptureCadence != "daily" {
			t.Errorf("CaptureCadence = %q", cfg.CaptureCadence)
		}
	})

	t.Run("invalid capture_cadence", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := UpdateAttribute(cfg, "capture_cadence", "weekly")
		if err == nil {
			t.Fatal("expected error for invalid cadence")
		}
	})
}

func TestResetAttribute(t *testing.T) {
	cfg := &WorkspacePolicy{MaxUnsafe: "168h"}
	if err := ResetAttribute(cfg, "max_unsafe"); err != nil {
		t.Fatalf("ResetAttribute() error: %v", err)
	}
	if cfg.MaxUnsafe != "" {
		t.Errorf("MaxUnsafe = %q, want empty", cfg.MaxUnsafe)
	}

	err := ResetAttribute(cfg, "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestConfigureLifecycleTier(t *testing.T) {
	t.Run("older_than", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		if err := ConfigureLifecycleTier(cfg, "hot", "older_than", "7d"); err != nil {
			t.Fatalf("error: %v", err)
		}
		if cfg.RetentionTiers["hot"].OlderThan != "7d" {
			t.Errorf("OlderThan = %q, want 7d", cfg.RetentionTiers["hot"].OlderThan)
		}
	})

	t.Run("keep_min", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		if err := ConfigureLifecycleTier(cfg, "hot", "keep_min", "5"); err != nil {
			t.Fatalf("error: %v", err)
		}
		if cfg.RetentionTiers["hot"].KeepMin != 5 {
			t.Errorf("KeepMin = %d, want 5", cfg.RetentionTiers["hot"].KeepMin)
		}
	})

	t.Run("default subfield is older_than", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		if err := ConfigureLifecycleTier(cfg, "hot", "", "14d"); err != nil {
			t.Fatalf("error: %v", err)
		}
		if cfg.RetentionTiers["hot"].OlderThan != "14d" {
			t.Errorf("OlderThan = %q, want 14d", cfg.RetentionTiers["hot"].OlderThan)
		}
	})

	t.Run("invalid duration", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := ConfigureLifecycleTier(cfg, "hot", "older_than", "bad")
		if err == nil {
			t.Fatal("expected error for invalid duration")
		}
	})

	t.Run("invalid keep_min", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := ConfigureLifecycleTier(cfg, "hot", "keep_min", "not-a-number")
		if err == nil {
			t.Fatal("expected error for invalid keep_min")
		}
	})

	t.Run("negative keep_min", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := ConfigureLifecycleTier(cfg, "hot", "keep_min", "-1")
		if err == nil {
			t.Fatal("expected error for negative keep_min")
		}
	})

	t.Run("unsupported subfield", func(t *testing.T) {
		cfg := &WorkspacePolicy{}
		err := ConfigureLifecycleTier(cfg, "hot", "bad_field", "value")
		if err == nil {
			t.Fatal("expected error for unsupported sub-field")
		}
	})
}

func TestRemoveLifecycleTier(t *testing.T) {
	cfg := &WorkspacePolicy{
		RetentionTiers: map[string]retention.Tier{
			"hot": {OlderThan: "7d"},
		},
	}
	RemoveLifecycleTier(cfg, "hot")
	if _, exists := cfg.RetentionTiers["hot"]; exists {
		t.Error("tier 'hot' should be deleted")
	}
}

func TestResolveAuditSetting(t *testing.T) {
	e := newTestEvaluator(&WorkspacePolicy{MaxUnsafe: "72h"}, nil)

	t.Run("known key", func(t *testing.T) {
		v, ok := ResolveAuditSetting(e, "max_unsafe")
		if !ok {
			t.Fatal("expected ok=true for max_unsafe")
		}
		if v.Value != "72h" {
			t.Errorf("Value = %q, want 72h", v.Value)
		}
	})

	t.Run("unknown key", func(t *testing.T) {
		_, ok := ResolveAuditSetting(e, "nonexistent")
		if ok {
			t.Error("expected ok=false for unknown key")
		}
	})

	t.Run("cli_output", func(t *testing.T) {
		v, ok := ResolveAuditSetting(e, "cli_output")
		if !ok {
			t.Fatal("expected ok=true for cli_output")
		}
		if v.Value != "text" {
			t.Errorf("Value = %q, want text", v.Value)
		}
	})
}

func TestBuildSettingCompletions(t *testing.T) {
	tiers := []string{"hot", "cold"}
	comps := BuildSettingCompletions(tiers)

	// Should include base config keys + tier expansions
	if len(comps) < len(GovernanceSettings)+6 { // 2 tiers * 3 variants
		t.Errorf("completions len = %d, expected at least %d", len(comps), len(GovernanceSettings)+6)
	}

	// Check tier completions exist
	found := map[string]bool{
		"snapshot_retention_tiers.hot":            false,
		"snapshot_retention_tiers.hot.older_than": false,
		"snapshot_retention_tiers.hot.keep_min":   false,
	}
	for _, c := range comps {
		if _, ok := found[c]; ok {
			found[c] = true
		}
	}
	for k, v := range found {
		if !v {
			t.Errorf("missing completion: %q", k)
		}
	}
}

func TestBuildEffectiveConfig(t *testing.T) {
	e := newTestEvaluator(
		&WorkspacePolicy{
			MaxUnsafe:       "72h",
			CIFailurePolicy: "fail_on_any_violation",
			RetentionTiers: map[string]retention.Tier{
				"hot": {OlderThan: "7d", KeepMin: 2},
			},
		},
		&OperatorSettings{
			CLIDefaults: OperatorCLIConfig{Output: "json"},
		},
	)

	eff := e.BuildEffectiveConfig()

	if eff.MaxUnsafeDuration.Value != "72h" {
		t.Errorf("MaxUnsafe = %q, want 72h", eff.MaxUnsafeDuration.Value)
	}
	if eff.CIFailurePolicy.Value != "fail_on_any_violation" {
		t.Errorf("CIFailurePolicy = %q", eff.CIFailurePolicy.Value)
	}
	if eff.CLIOutput.Value != "json" {
		t.Errorf("CLIOutput = %q, want json", eff.CLIOutput.Value)
	}
	if eff.ConfigFile != "/proj/stave.yaml" {
		t.Errorf("ConfigFile = %q, want /proj/stave.yaml", eff.ConfigFile)
	}
	if eff.UserConfigFile != "/home/.config/stave/config.yaml" {
		t.Errorf("UserConfigFile = %q", eff.UserConfigFile)
	}
	if _, ok := eff.DefinedRetentionTiers["hot"]; !ok {
		t.Error("missing 'hot' in DefinedRetentionTiers")
	}
	if _, ok := eff.EffectiveRetentionByTier["hot"]; !ok {
		t.Error("missing 'hot' in EffectiveRetentionByTier")
	}
}

func TestBuildEffectiveConfig_NoProject(t *testing.T) {
	e := &GovernanceResolver{Getenv: noEnv}
	eff := e.BuildEffectiveConfig()

	if eff.ConfigFile != "" {
		t.Errorf("ConfigFile = %q, want empty", eff.ConfigFile)
	}
	// Should still have default retention tier
	if _, ok := eff.DefinedRetentionTiers[DefaultRetentionTier]; !ok {
		t.Errorf("missing default tier %q in %v", DefaultRetentionTier, eff.DefinedRetentionTiers)
	}
}

func TestGovernanceSettings_ContainsExpected(t *testing.T) {
	expected := []string{"max_unsafe", "snapshot_retention", "ci_failure_policy", "capture_cadence"}
	for _, k := range expected {
		found := slices.Contains(GovernanceSettings, k)
		if !found {
			t.Errorf("GovernanceSettings missing %q", k)
		}
	}
}

func TestValidateField_CaptureAdence(t *testing.T) {
	cfg := &WorkspacePolicy{CaptureCadence: "weekly"}
	err := validateAuditSetting(cfg, "CaptureCadence")
	if err == nil {
		t.Fatal("expected error for invalid cadence")
	}
	if !strings.Contains(err.Error(), "daily") {
		t.Errorf("error = %q, should mention valid values", err.Error())
	}
}

func TestValidateField_EmptyValues(t *testing.T) {
	cfg := &WorkspacePolicy{}
	// Empty values should pass validation
	for _, field := range []string{"MaxUnsafe", "SnapshotRetention", "RetentionTier", "CIFailurePolicy", "CaptureCadence", "SnapshotFilenameTemplate"} {
		if err := validateAuditSetting(cfg, field); err != nil {
			t.Errorf("validateAuditSetting(%q) with empty value: %v", field, err)
		}
	}
}

func TestSnapshotRetentionForTier(t *testing.T) {
	e := newTestEvaluator(&WorkspacePolicy{
		RetentionTiers: map[string]retention.Tier{
			"hot": {OlderThan: "3d"},
		},
	}, nil)
	if got := e.SnapshotRetentionForTier("hot"); got != "3d" {
		t.Errorf("got %q, want 3d", got)
	}
}
