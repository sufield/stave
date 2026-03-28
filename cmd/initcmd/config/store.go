package config

import (
	"fmt"
	"path/filepath"
	"strconv"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/core/retention"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// projectConfigStore implements cliconfig.Store[appconfig.ProjectConfig].
// It acts as the infrastructure adapter for the stave.yaml file.
type projectConfigStore struct {
	resolver     *projconfig.Resolver
	allowSymlink bool
}

// Find attempts to locate an existing project configuration.
func (s projectConfigStore) Find() (*appconfig.ProjectConfig, string, bool) {
	if s.resolver == nil {
		cfg, path, err := projconfig.FindProjectConfigWithPath("")
		if err != nil {
			return nil, "", false
		}
		return cfg, path, cfg != nil
	}
	cfg, path, err := s.resolver.FindProjectConfig("")
	if err != nil {
		return nil, "", false
	}
	return cfg, path, true
}

// LoadOrCreate finds the config file or prepares a new one in the working directory.
func (s projectConfigStore) LoadOrCreate() (*appconfig.ProjectConfig, string, error) {
	cfg, cfgPath, ok := s.Find()
	if ok {
		if cfg == nil {
			cfg = &appconfig.ProjectConfig{}
		}
		return cfg, cfgPath, nil
	}

	baseDir := "."
	if s.resolver != nil && s.resolver.WorkingDir != "" {
		baseDir = s.resolver.WorkingDir
	}
	return &appconfig.ProjectConfig{}, filepath.Join(baseDir, appconfig.ProjectConfigFile), nil
}

// CurrentValue resolves the effective value of a key for display during
// interactive editing. Returns (value, true) when set, or ("", false)
// when unset, following Go's comma-ok idiom.
func (s projectConfigStore) CurrentValue(cfg *appconfig.ProjectConfig, key, cfgPath string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	eval := appconfig.NewEvaluator(cfg, cfgPath, nil, "")

	parsed, err := appconfig.ParseConfigKey(key)
	if err != nil {
		return "", false
	}

	if parsed.TierName != "" {
		if parsed.SubField != "" {
			return s.tierSubFieldValue(cfg, parsed)
		}
		v := eval.ResolveSnapshotRetention(parsed.TierName)
		if v.Value == "" {
			return "", false
		}
		return v.Value, true
	}

	if parsed.TopLevel == "snapshot_retention" {
		v := eval.ResolveSnapshotRetention(eval.RetentionTier())
		if v.Value == "" {
			return "", false
		}
		return v.Value, true
	}

	v, ok := appconfig.ResolveKey(eval, key)
	if !ok || v.Value == "" {
		return "", false
	}
	return v.Value, true
}

func (s projectConfigStore) tierSubFieldValue(cfg *appconfig.ProjectConfig, parsed appconfig.ParsedKey) (string, bool) {
	if cfg == nil || len(cfg.RetentionTiers) == 0 {
		return "", false
	}
	tc, exists := cfg.RetentionTiers[parsed.TierName]
	if !exists {
		return "", false
	}
	switch parsed.SubField {
	case "older_than":
		if tc.OlderThan == "" {
			return "", false
		}
		return tc.OlderThan, true
	case "keep_min":
		return strconv.Itoa(retention.TierConfig{KeepMin: tc.KeepMin}.EffectiveKeepMin()), true
	default:
		return "", false
	}
}

// Set updates a specific key in the provided config struct.
func (s projectConfigStore) Set(cfg *appconfig.ProjectConfig, key, value string) error {
	parsed, err := appconfig.ParseConfigKey(key)
	if err != nil {
		return err
	}
	if parsed.TierName != "" {
		return appconfig.SetTierValue(cfg, parsed.TierName, parsed.SubField, value)
	}
	return appconfig.SetConfigValue(cfg, parsed.TopLevel, value)
}

// Delete removes a specific key from the provided config struct.
func (s projectConfigStore) Delete(cfg *appconfig.ProjectConfig, key string) error {
	parsed, err := appconfig.ParseConfigKey(key)
	if err != nil {
		return err
	}
	if parsed.TierName != "" {
		appconfig.DeleteTierValue(cfg, parsed.TierName)
		return nil
	}
	return appconfig.DeleteConfigValue(cfg, parsed.TopLevel)
}

// Write serializes the configuration back to the stave.yaml file.
func (s projectConfigStore) Write(path string, cfg *appconfig.ProjectConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling configuration: %w", err)
	}
	opts := fsutil.ConfigWriteOpts()
	opts.AllowSymlink = s.allowSymlink
	if err := fsutil.SafeWriteFile(path, data, opts); err != nil {
		return fmt.Errorf("writing configuration to %q: %w", path, err)
	}
	return nil
}
