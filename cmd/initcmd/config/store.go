package config

import (
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// projectConfigStore implements cliconfig.Store[projconfig.ProjectConfig].
// It acts as the infrastructure adapter for the stave.yaml file.
type projectConfigStore struct {
	resolver     *projconfig.Resolver
	svc          *configservice.Service
	allowSymlink bool
}

// Find attempts to locate an existing project configuration.
func (s projectConfigStore) Find() (*projconfig.ProjectConfig, string, bool) {
	if s.resolver == nil {
		return projconfig.FindProjectConfigWithPath("")
	}
	cfg, path, err := s.resolver.FindProjectConfig("")
	if err != nil {
		return nil, "", false
	}
	return cfg, path, true
}

// LoadOrCreate finds the config file or prepares a new one in the working directory.
func (s projectConfigStore) LoadOrCreate() (*projconfig.ProjectConfig, string, error) {
	cfg, cfgPath, ok := s.Find()
	if ok {
		if cfg == nil {
			cfg = &projconfig.ProjectConfig{}
		}
		return cfg, cfgPath, nil
	}

	baseDir := "."
	if s.resolver != nil && s.resolver.WorkingDir != "" {
		baseDir = s.resolver.WorkingDir
	}
	return &projconfig.ProjectConfig{}, filepath.Join(baseDir, projconfig.ProjectConfigFile), nil
}

// CurrentValue resolves the effective value of a key for display during interactive editing.
func (s projectConfigStore) CurrentValue(cfg *projconfig.ProjectConfig, key, cfgPath string) string {
	if cfg == nil {
		return "(not set)"
	}
	eval := projconfig.NewEvaluator(cfg, cfgPath, nil, "")
	kv, err := resolveServiceConfigKeyValue(s.svc, key, cfg, cfgPath, eval.RetentionTier())
	if err != nil || kv.Value == "" {
		return "(not set)"
	}
	return kv.Value
}

// Set updates a specific key in the provided config struct.
func (s projectConfigStore) Set(cfg *projconfig.ProjectConfig, key, value string) error {
	parsed, err := s.svc.ParseConfigKey(key)
	if err != nil {
		return err
	}
	return projconfig.MutateProjectConfig(cfg, func(serviceCfg *configservice.Config) error {
		return s.svc.SetConfigKeyValue(serviceCfg, parsed, value)
	})
}

// Delete removes a specific key from the provided config struct.
func (s projectConfigStore) Delete(cfg *projconfig.ProjectConfig, key string) error {
	parsed, err := s.svc.ParseConfigKey(key)
	if err != nil {
		return err
	}
	return projconfig.MutateProjectConfig(cfg, func(serviceCfg *configservice.Config) error {
		return s.svc.DeleteConfigKeyValue(serviceCfg, parsed)
	})
}

// Write serializes the configuration back to the stave.yaml file.
func (s projectConfigStore) Write(path string, cfg *projconfig.ProjectConfig) error {
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

// resolveServiceConfigKeyValue resolves a config key to its effective value and source.
func resolveServiceConfigKeyValue(svc *configservice.Service, key string, cfg *projconfig.ProjectConfig, cfgPath, fallbackTier string) (configservice.KeyValueOutput, error) {
	parsed, err := svc.ParseConfigKey(key)
	if err != nil {
		return configservice.KeyValueOutput{}, err
	}
	return svc.ResolveConfigKeyValue(parsed, projconfig.FromProjectConfig(cfg), cfgPath, fallbackTier)
}
