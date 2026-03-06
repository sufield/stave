package cmdutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/envvar"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// FindNearestFile walks up from cwd looking for filename.
func FindNearestFile(filename string) (string, bool) {
	wd, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for {
		path := filepath.Join(wd, filename)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", false
		}
		wd = parent
	}
}

// FindProjectConfig returns the nearest project config.
func FindProjectConfig() (*ProjectConfig, bool) {
	cfg, _, ok := FindProjectConfigWithPath()
	return cfg, ok
}

// FindProjectConfigWithPath returns the config, its path, and whether found.
func FindProjectConfigWithPath() (*ProjectConfig, string, bool) {
	if path, ok := ResolveContextConfigFilePath(""); ok {
		// #nosec G304 -- path is resolved from local project context config discovery.
		data, err := os.ReadFile(path)
		if err == nil {
			var cfg ProjectConfig
			if err := yaml.Unmarshal(data, &cfg); err == nil {
				return &cfg, path, true
			}
		}
	}

	path, ok := FindNearestFile(ProjectConfigFile)
	if !ok {
		return nil, "", false
	}
	// #nosec G304 -- path is resolved by walking parent directories for the project config file.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", false
	}
	var cfg ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, "", false
	}
	return &cfg, path, true
}

// FindUserConfigPath returns the user config path.
func FindUserConfigPath() (string, bool) {
	if override := strings.TrimSpace(os.Getenv(envvar.UserConfig.Name)); override != "" {
		return override, true
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", false
	}
	return filepath.Join(home, ".config", "stave", "config.yaml"), true
}

// FindUserConfig returns the user config.
func FindUserConfig() (*UserConfig, bool) {
	cfg, _, ok := FindUserConfigWithPath()
	return cfg, ok
}

// FindUserConfigWithPath returns the user config, path, and whether found.
func FindUserConfigWithPath() (*UserConfig, string, bool) {
	path, ok := FindUserConfigPath()
	if !ok {
		return nil, "", false
	}
	// #nosec G304 -- path is resolved from local user config location or explicit env override.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", false
	}
	var cfg UserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, "", false
	}
	return &cfg, path, true
}

// LoadUserAliases returns the alias map from user config, or nil if none.
func LoadUserAliases() map[string]string {
	cfg, ok := FindUserConfig()
	if !ok || cfg.Aliases == nil {
		return nil
	}
	return cfg.Aliases
}

// LoadUserConfigFull loads the full user config struct and its path.
func LoadUserConfigFull() (*UserConfig, string) {
	cfg, path, ok := FindUserConfigWithPath()
	if ok && cfg != nil {
		return cfg, path
	}
	p, _ := FindUserConfigPath()
	return &UserConfig{}, p
}

// WriteUserConfigFull marshals and writes the user config to the given path.
func WriteUserConfigFull(cfg *UserConfig, path string) error {
	outBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal user config: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory %s: %w", dir, err)
	}
	return fsutil.SafeWriteFile(path, outBytes, fsutil.ConfigWriteOpts())
}
