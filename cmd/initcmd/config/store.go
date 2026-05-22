package config

import (
	"fmt"
	"path/filepath"

	appconfig "github.com/sufield/stave/internal/app/config"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// projectConfigStore implements cliconfig.Store[appconfig.WorkspacePolicy].
// It acts as the infrastructure adapter for the stave.yaml file.
type projectConfigStore struct {
	resolver     *projconfig.Resolver
	allowSymlink bool
}

// Find attempts to locate an existing project configuration.
func (s projectConfigStore) Find() (*appconfig.WorkspacePolicy, string, bool) {
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
func (s projectConfigStore) LoadOrCreate() (*appconfig.WorkspacePolicy, string, error) {
	cfg, cfgPath, ok := s.Find()
	if ok {
		if cfg == nil {
			cfg = &appconfig.WorkspacePolicy{}
		}
		return cfg, cfgPath, nil
	}

	baseDir := "."
	if s.resolver != nil && s.resolver.WorkingDir != "" {
		baseDir = s.resolver.WorkingDir
	}
	return &appconfig.WorkspacePolicy{}, filepath.Join(baseDir, appconfig.AuditPolicyFile), nil
}

// CurrentValue resolves the effective value of a key for display during
// interactive editing. Returns (value, true) when set, or ("", false)
// when unset, following Go's comma-ok idiom.
func (s projectConfigStore) CurrentValue(cfg *appconfig.WorkspacePolicy, key, cfgPath string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	eval := appconfig.NewResolver(cfg, cfgPath, nil, "")

	if _, err := appconfig.IdentifySetting(key); err != nil {
		return "", false
	}

	v, ok := appconfig.ResolveAuditSetting(eval, key)
	if !ok || v.Value == "" {
		return "", false
	}
	return v.Value, true
}

// Set updates a specific key in the provided config struct.
func (s projectConfigStore) Set(cfg *appconfig.WorkspacePolicy, key, value string) error {
	parsed, err := appconfig.IdentifySetting(key)
	if err != nil {
		return err
	}
	return appconfig.UpdateAttribute(cfg, parsed.Attribute, value)
}

// Delete removes a specific key from the provided config struct.
func (s projectConfigStore) Delete(cfg *appconfig.WorkspacePolicy, key string) error {
	parsed, err := appconfig.IdentifySetting(key)
	if err != nil {
		return err
	}
	return appconfig.ResetAttribute(cfg, parsed.Attribute)
}

// Write serializes the configuration back to the stave.yaml file.
func (s projectConfigStore) Write(path string, cfg *appconfig.WorkspacePolicy) error {
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
