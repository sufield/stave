package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/configservice"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// projectConfigStore implements cliconfig.Store[projconfig.ProjectConfig].
// svc must not be nil; it is always set from the configCommand that owns this
// store, which in turn receives it from NewConfigCmd's required parameter.
type projectConfigStore struct {
	allowSymlink bool
	svc          *configservice.Service
}

func (s projectConfigStore) Find() (*projconfig.ProjectConfig, string, bool) {
	return projconfig.FindProjectConfigWithPath("")
}

func (s projectConfigStore) LoadOrCreate() (*projconfig.ProjectConfig, string, error) {
	cfg, cfgPath, existed := projconfig.FindProjectConfigWithPath("")
	if existed {
		if cfg == nil {
			cfg = &projconfig.ProjectConfig{}
		}
		return cfg, cfgPath, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, "", err
	}
	return &projconfig.ProjectConfig{}, filepath.Join(wd, projconfig.ProjectConfigFile), nil
}

func (s projectConfigStore) CurrentValue(cfg *projconfig.ProjectConfig, key, cfgPath string) string {
	if cfg == nil {
		return "(not set)"
	}
	eval := projconfig.NewEvaluator(cfg, cfgPath, nil, "")
	retTier := eval.RetentionTier()
	kv, err := resolveServiceConfigKeyValue(s.svc, key, cfg, cfgPath, retTier.Value)
	if err != nil || kv.Value == "" {
		return "(not set)"
	}
	return kv.Value
}

func (s projectConfigStore) Set(cfg *projconfig.ProjectConfig, key, value string) error {
	return setConfigKeyValue(s.svc, cfg, key, value)
}

func (s projectConfigStore) Delete(cfg *projconfig.ProjectConfig, key string) error {
	return deleteConfigKeyValue(s.svc, cfg, key)
}

func (s projectConfigStore) Write(path string, cfg *projconfig.ProjectConfig) error {
	outBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", projconfig.ProjectConfigFile, err)
	}
	opts := fsutil.ConfigWriteOpts()
	opts.AllowSymlink = s.allowSymlink
	if err := fsutil.SafeWriteFile(path, outBytes, opts); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func resolveServiceConfigKeyValue(svc *configservice.Service, key string, cfg *projconfig.ProjectConfig, cfgPath, fallbackTier string) (configservice.KeyValueOutput, error) {
	parsed, err := svc.ParseConfigKey(key)
	if err != nil {
		return configservice.KeyValueOutput{}, err
	}
	return svc.ResolveConfigKeyValue(parsed, projconfig.FromProjectConfig(cfg), cfgPath, fallbackTier)
}

func deleteConfigKeyValue(svc *configservice.Service, cfg *projconfig.ProjectConfig, key string) error {
	parsed, err := svc.ParseConfigKey(key)
	if err != nil {
		return err
	}
	return projconfig.MutateProjectConfig(cfg, func(serviceCfg *configservice.Config) error {
		return svc.DeleteConfigKeyValue(serviceCfg, parsed)
	})
}

func setConfigKeyValue(svc *configservice.Service, cfg *projconfig.ProjectConfig, key, value string) error {
	parsed, err := svc.ParseConfigKey(key)
	if err != nil {
		return err
	}
	return projconfig.MutateProjectConfig(cfg, func(serviceCfg *configservice.Config) error {
		return svc.SetConfigKeyValue(serviceCfg, parsed, value)
	})
}
