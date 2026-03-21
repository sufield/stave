package projconfig

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// ErrConfigNotFound indicates that no configuration file could be located.
var ErrConfigNotFound = errors.New("configuration file not found")

// Resolver handles the discovery and loading of configuration files.
type Resolver struct {
	WorkingDir string
	HomeDir    string
}

// NewResolver initializes a resolver with system defaults.
func NewResolver() (*Resolver, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	return &Resolver{
		WorkingDir: wd,
		HomeDir:    home,
	}, nil
}

// --- Project Config Logic ---

// FindProjectConfig searches for the project configuration file by walking up
// the directory tree starting from the resolver's WorkingDir.
func (r *Resolver) FindProjectConfig(contextPath string) (*appconfig.ProjectConfig, string, error) {
	// 1. Priority: Explicit context path (passed from CLI layer).
	// If loading fails, return the error — do not silently fall back
	// to a different config from cwd ancestry.
	if contextPath != "" {
		cfg, err := r.loadProjectConfig(contextPath)
		if err != nil {
			return nil, contextPath, fmt.Errorf("load config from context path %q: %w", contextPath, err)
		}
		return cfg, contextPath, nil
	}

	// 2. Secondary: Walk up from working directory
	path, ok := r.NearestFile(appconfig.ProjectConfigFile)
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", ErrConfigNotFound, appconfig.ProjectConfigFile)
	}

	cfg, err := r.loadProjectConfig(path)
	if err != nil {
		return nil, path, err
	}

	return cfg, path, nil
}

// NearestFile walks up from WorkingDir looking for a file with the given name.
func (r *Resolver) NearestFile(filename string) (string, bool) {
	curr := r.WorkingDir
	for {
		path := filepath.Join(curr, filename)
		if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
			return path, true
		}
		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}
	return "", false
}

func (r *Resolver) loadProjectConfig(path string) (*appconfig.ProjectConfig, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read project config: %w", err)
	}
	var cfg appconfig.ProjectConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse project config at %q: %w", path, err)
	}
	return &cfg, nil
}

// --- User Config Logic ---

// UserConfigPath returns the determined path for global user configuration.
func (r *Resolver) UserConfigPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv(env.UserConfig.Name)); override != "" {
		return override, nil
	}
	if r.HomeDir == "" {
		return "", errors.New("home directory not available")
	}
	return filepath.Join(r.HomeDir, ".config", "stave", "config.yaml"), nil
}

// LoadUserConfig finds and parses the user's global configuration.
func (r *Resolver) LoadUserConfig() (*appconfig.UserConfig, string, error) {
	path, err := r.UserConfigPath()
	if err != nil {
		return nil, "", err
	}

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &appconfig.UserConfig{}, path, nil
		}
		return nil, path, fmt.Errorf("read user config: %w", err)
	}

	var cfg appconfig.UserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, path, fmt.Errorf("parse user config at %q: %w", path, err)
	}
	return &cfg, path, nil
}

// WriteUserConfig persists the user configuration to disk.
func (r *Resolver) WriteUserConfig(cfg *appconfig.UserConfig, path string) error {
	outBytes, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal user config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := fsutil.SafeMkdirAll(dir, fsutil.WriteOptions{Perm: 0o700}); err != nil {
		return fmt.Errorf("create config directory %q: %w", dir, err)
	}

	return fsutil.SafeWriteFile(path, outBytes, fsutil.ConfigWriteOpts())
}

// --- Package-level convenience functions ---

// defaultResolver returns a resolver with system defaults.
// Returns nil on error (callers fall through to not-found).
func defaultResolver() *Resolver {
	r, err := NewResolver()
	if err != nil {
		return nil
	}
	return r
}

// FindNearestFile walks up from cwd looking for filename.
func FindNearestFile(filename string) (string, bool) {
	r := defaultResolver()
	if r == nil {
		return "", false
	}
	return r.NearestFile(filename)
}

// FindProjectConfig returns the nearest project config.
// Returns (nil, false, nil) when no config file is found.
// Returns a non-nil error for parse or permission failures.
func FindProjectConfig() (*appconfig.ProjectConfig, bool, error) {
	cfg, _, err := FindProjectConfigWithPath("")
	if err != nil {
		return nil, false, err
	}
	return cfg, cfg != nil, nil
}

// FindProjectConfigWithPath returns the config and its path.
// Returns (nil, "", nil) when no config file is found (ErrConfigNotFound).
// Returns a non-nil error for parse failures, permission errors, or
// explicit context path load failures — these should not be silenced.
func FindProjectConfigWithPath(contextPath string) (*appconfig.ProjectConfig, string, error) {
	r := defaultResolver()
	if r == nil {
		return nil, "", nil
	}
	cfg, path, err := r.FindProjectConfig(contextPath)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			return nil, "", nil
		}
		return nil, path, err
	}
	return cfg, path, nil
}

// FindUserConfigWithPath returns the user config, path, and whether found.
// Returns a non-nil error for parse or permission failures (as opposed to
// the config simply not existing, which returns found=false with nil error).
func FindUserConfigWithPath() (*appconfig.UserConfig, string, bool, error) {
	r := defaultResolver()
	if r == nil {
		return nil, "", false, nil
	}
	cfg, path, err := r.LoadUserConfig()
	if err != nil {
		return nil, "", false, err
	}
	return cfg, path, true, nil
}

// LoadUserAliases returns the alias map from user config, or nil if none.
// Logs a warning if the user config fails to load (rather than silently ignoring).
func LoadUserAliases() map[string]string {
	cfg, _, ok, err := FindUserConfigWithPath()
	if err != nil {
		slog.Warn("failed to load user config for aliases", "error", err)
	}
	if !ok || cfg == nil || cfg.Aliases == nil {
		return nil
	}
	return cfg.Aliases
}
