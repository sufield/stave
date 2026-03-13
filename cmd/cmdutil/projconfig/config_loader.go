package projconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	home, _ := os.UserHomeDir()
	return &Resolver{
		WorkingDir: wd,
		HomeDir:    home,
	}, nil
}

// --- Project Config Logic ---

// FindProjectConfig searches for the project configuration file by walking up
// the directory tree starting from the resolver's WorkingDir.
func (r *Resolver) FindProjectConfig(contextPath string) (*ProjectConfig, string, error) {
	// 1. Priority: Explicit context path (passed from CLI layer)
	if contextPath != "" {
		cfg, err := r.loadProjectConfig(contextPath)
		if err == nil {
			return cfg, contextPath, nil
		}
	}

	// 2. Secondary: Walk up from working directory
	path, ok := r.NearestFile(ProjectConfigFile)
	if !ok {
		return nil, "", fmt.Errorf("%w: %s", ErrConfigNotFound, ProjectConfigFile)
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

func (r *Resolver) loadProjectConfig(path string) (*ProjectConfig, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read project config: %w", err)
	}
	var cfg ProjectConfig
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
func (r *Resolver) LoadUserConfig() (*UserConfig, string, error) {
	path, err := r.UserConfigPath()
	if err != nil {
		return nil, "", err
	}

	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &UserConfig{}, path, nil
		}
		return nil, path, fmt.Errorf("read user config: %w", err)
	}

	var cfg UserConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, path, fmt.Errorf("parse user config at %q: %w", path, err)
	}
	return &cfg, path, nil
}

// WriteUserConfig persists the user configuration to disk.
func (r *Resolver) WriteUserConfig(cfg *UserConfig, path string) error {
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
func FindProjectConfig() (*ProjectConfig, bool) {
	cfg, _, ok := FindProjectConfigWithPath("")
	return cfg, ok
}

// FindProjectConfigWithPath returns the config, its path, and whether found.
// If contextPath is non-empty, it is checked first before walking up from cwd.
func FindProjectConfigWithPath(contextPath string) (*ProjectConfig, string, bool) {
	r := defaultResolver()
	if r == nil {
		return nil, "", false
	}
	cfg, path, err := r.FindProjectConfig(contextPath)
	if err != nil {
		return nil, "", false
	}
	return cfg, path, true
}

// FindUserConfigWithPath returns the user config, path, and whether found.
func FindUserConfigWithPath() (*UserConfig, string, bool) {
	r := defaultResolver()
	if r == nil {
		return nil, "", false
	}
	cfg, path, err := r.LoadUserConfig()
	if err != nil {
		return nil, "", false
	}
	return cfg, path, true
}

// LoadUserAliases returns the alias map from user config, or nil if none.
func LoadUserAliases() map[string]string {
	cfg, _, ok := FindUserConfigWithPath()
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
	r := defaultResolver()
	if r == nil {
		return &UserConfig{}, ""
	}
	p, _ := r.UserConfigPath()
	return &UserConfig{}, p
}

// WriteUserConfigFull marshals and writes the user config to the given path.
func WriteUserConfigFull(cfg *UserConfig, path string) error {
	r := defaultResolver()
	if r == nil {
		r = &Resolver{}
	}
	return r.WriteUserConfig(cfg, path)
}
