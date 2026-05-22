package config

import (
	"fmt"

	appconfig "github.com/sufield/stave/internal/app/config"
)

// resolveConfigValue dispatches key resolution to the appropriate strategy.
func resolveConfigValue(cfg *appconfig.WorkspacePolicy, cfgPath string, eval *appconfig.GovernanceResolver, parsed appconfig.SettingPath) (ValueResult, error) {
	key := parsed.Raw

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
