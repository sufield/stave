package config

import (
	"fmt"
	"strconv"

	appconfig "github.com/sufield/stave/internal/app/config"

	"github.com/sufield/stave/internal/core/retention"
)

// resolveConfigValue dispatches key resolution to the appropriate strategy.
func resolveConfigValue(cfg *appconfig.WorkspacePolicy, cfgPath string, eval *appconfig.GovernanceResolver, parsed appconfig.SettingPath) (ValueResult, error) {
	key := parsed.Raw

	// Tier keys: snapshot_retention_tiers.<tier>[.<field>]
	if parsed.TierName != "" {
		return resolveTierKey(cfg, cfgPath, eval, parsed)
	}

	// Known keys with special resolution logic.
	if resolver, ok := specialResolvers[parsed.Attribute]; ok {
		return resolver(cfg, cfgPath, eval, parsed)
	}

	// Generic top-level key: evaluator method or direct config field.
	if v, ok := appconfig.ResolveAuditSetting(eval, key); ok {
		return ValueResult{Key: key, Value: v.Value, Source: v.Source}, nil
	}
	if cfg != nil {
		if val, found := appconfig.GetAttribute(cfg, key); found {
			return ValueResult{Key: key, Value: val, Source: cfgPath + ":" + key}, nil
		}
	}
	return ValueResult{}, fmt.Errorf("key %q: not set", key)
}

// specialResolvers maps top-level keys that need custom resolution logic.
var specialResolvers = map[string]func(*appconfig.WorkspacePolicy, string, *appconfig.GovernanceResolver, appconfig.SettingPath) (ValueResult, error){
	"snapshot_retention": func(_ *appconfig.WorkspacePolicy, _ string, eval *appconfig.GovernanceResolver, p appconfig.SettingPath) (ValueResult, error) { //nolint:unparam // error is part of the resolver func signature
		v := eval.ResolveSnapshotRetention(eval.RetentionTier())
		return ValueResult{Key: p.Raw, Value: v.Value, Source: v.Source}, nil
	},
	"capture_cadence": func(cfg *appconfig.WorkspacePolicy, cfgPath string, _ *appconfig.GovernanceResolver, p appconfig.SettingPath) (ValueResult, error) {
		if cfg == nil || cfg.CaptureCadence == "" {
			return ValueResult{}, fmt.Errorf("key %q: not set in %s", p.Raw, appconfig.AuditPolicyFile)
		}
		return ValueResult{Key: p.Raw, Value: cfg.CaptureCadence, Source: cfgPath + ":capture_cadence"}, nil
	},
	"snapshot_filename_template": func(cfg *appconfig.WorkspacePolicy, cfgPath string, _ *appconfig.GovernanceResolver, p appconfig.SettingPath) (ValueResult, error) {
		if cfg == nil || cfg.SnapshotFilenameTemplate == "" {
			return ValueResult{}, fmt.Errorf("key %q: not set in %s", p.Raw, appconfig.AuditPolicyFile)
		}
		return ValueResult{Key: p.Raw, Value: cfg.SnapshotFilenameTemplate, Source: cfgPath + ":snapshot_filename_template"}, nil
	},
}

func resolveTierKey(cfg *appconfig.WorkspacePolicy, cfgPath string, eval *appconfig.GovernanceResolver, parsed appconfig.SettingPath) (ValueResult, error) {
	if parsed.Property != "" {
		val, source, err := tierSubFieldResolution(cfg, cfgPath, parsed)
		if err != nil {
			return ValueResult{}, err
		}
		return ValueResult{Key: parsed.Raw, Value: val, Source: source}, nil
	}
	v := eval.ResolveSnapshotRetention(parsed.TierName)
	return ValueResult{Key: parsed.Raw, Value: v.Value, Source: v.Source}, nil
}

// tierSubFieldResolution reads a specific tier sub-field directly from config.
func tierSubFieldResolution(cfg *appconfig.WorkspacePolicy, cfgPath string, parsed appconfig.SettingPath) (resolvedValue, source string, err error) {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return "", "", fmt.Errorf("key %q: not set in %s", parsed.Raw, appconfig.AuditPolicyFile)
	}
	tc, exists := cfg.RetentionTiers[parsed.TierName]
	if !exists {
		return "", "", fmt.Errorf("tier %q is not configured", parsed.TierName)
	}

	var val string
	switch parsed.Property {
	case "older_than":
		val = tc.OlderThan
	case "keep_min":
		val = strconv.Itoa(retention.Tier{KeepMin: tc.KeepMin}.MinRetained())
	default:
		return "", "", fmt.Errorf("unsupported tier field %q", parsed.Property)
	}

	source = fmt.Sprintf("%s:%s%s.%s", cfgPath, appconfig.RetentionPrefix, parsed.TierName, parsed.Property)
	return val, source, nil
}
