package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// projectConfigStore implements cliconfig.Store[cmdutil.ProjectConfig].
type projectConfigStore struct {
	allowSymlink bool
}

func (s projectConfigStore) Find() (*cmdutil.ProjectConfig, string, bool) {
	return cmdutil.FindProjectConfigWithPath()
}

func (s projectConfigStore) LoadOrCreate() (*cmdutil.ProjectConfig, string, error) {
	cfg, cfgPath, existed := cmdutil.FindProjectConfigWithPath()
	if existed {
		if cfg == nil {
			cfg = &cmdutil.ProjectConfig{}
		}
		return cfg, cfgPath, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, "", err
	}
	return &cmdutil.ProjectConfig{}, filepath.Join(wd, cmdutil.ProjectConfigFile), nil
}

func (s projectConfigStore) CurrentValue(cfg *cmdutil.ProjectConfig, key, cfgPath string) string {
	if cfg == nil {
		return "(not set)"
	}
	retTier := cmdutil.ResolveRetentionTierWithSource(cfg, cfgPath)
	kv, err := resolveServiceConfigKeyValue(key, cfg, cfgPath, retTier.Value)
	if err != nil || kv.Value == "" {
		return "(not set)"
	}
	return kv.Value
}

func (s projectConfigStore) Set(cfg *cmdutil.ProjectConfig, key, value string) error {
	return setConfigKeyValue(cfg, key, value)
}

func (s projectConfigStore) Delete(cfg *cmdutil.ProjectConfig, key string) error {
	return deleteConfigKeyValue(cfg, key)
}

func (s projectConfigStore) Write(path string, cfg *cmdutil.ProjectConfig) error {
	outBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", cmdutil.ProjectConfigFile, err)
	}
	opts := fsutil.ConfigWriteOpts()
	opts.AllowSymlink = s.allowSymlink
	if err := fsutil.SafeWriteFile(path, outBytes, opts); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func resolveServiceConfigKeyValue(key string, cfg *cmdutil.ProjectConfig, cfgPath, fallbackTier string) (configservice.KeyValueOutput, error) {
	return cmdutil.ConfigKeyService.ResolveConfigKeyValue(key, cmdutil.FromProjectConfig(cfg), cfgPath, fallbackTier)
}

func deleteConfigKeyValue(cfg *cmdutil.ProjectConfig, key string) error {
	return cmdutil.MutateProjectConfig(cfg, func(serviceCfg *configservice.Config) error {
		return cmdutil.ConfigKeyService.DeleteConfigKeyValue(serviceCfg, key)
	})
}

func setConfigKeyValue(cfg *cmdutil.ProjectConfig, key, value string) error {
	return cmdutil.MutateProjectConfig(cfg, func(serviceCfg *configservice.Config) error {
		return cmdutil.ConfigKeyService.SetConfigKeyValue(serviceCfg, key, value)
	})
}
