package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ErrContextNotFound is returned when a named context does not exist in the store.
var ErrContextNotFound = errors.New("context not found")

// ErrNoConfigDir is returned when neither config dir nor home dir can be resolved.
var ErrNoConfigDir = errors.New("could not resolve a config directory or user home")

type Defaults struct {
	ControlsDir     string `yaml:"controls_dir,omitempty"`
	ObservationsDir string `yaml:"observations_dir,omitempty"`
}

type Context struct {
	ProjectRoot   string   `yaml:"project_root"`
	ProjectConfig string   `yaml:"project_config,omitempty"`
	Defaults      Defaults `yaml:"defaults,omitempty"`
}

type Store struct {
	Active   string             `yaml:"active,omitempty"`
	Contexts map[string]Context `yaml:"contexts,omitempty"`
	path     string             `yaml:"-"`
}

// NewStore initializes a Store with a ready-to-use context map.
func NewStore() *Store {
	return &Store{
		Contexts: make(map[string]Context),
	}
}

// UnmarshalYAML ensures a decoded Store always has a non-nil Contexts map.
func (s *Store) UnmarshalYAML(value *yaml.Node) error {
	type alias Store
	var tmp alias
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	*s = Store(tmp)
	if s.Contexts == nil {
		s.Contexts = make(map[string]Context)
	}
	return nil
}

func resolveStorePath() (string, error) {
	if v := strings.TrimSpace(os.Getenv(env.ContextsFile.Name)); v != "" {
		return v, nil
	}
	if cfgDir, err := os.UserConfigDir(); err == nil && strings.TrimSpace(cfgDir) != "" {
		return filepath.Join(cfgDir, "stave", "contexts.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return "", ErrNoConfigDir
	}
	return filepath.Join(home, ".config", "stave", "contexts.yaml"), nil
}

// Load reads the context store from disk.
func Load() (*Store, string, error) {
	path, err := resolveStorePath()
	if err != nil {
		return nil, "", err
	}

	st := NewStore()
	st.path = path

	// #nosec G304 -- path comes from a local config location or explicit STAVE_CONTEXTS_FILE override.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, path, nil
		}
		return nil, "", fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, st); err != nil {
		return nil, "", fmt.Errorf("parse yaml at %s: %w", path, err)
	}

	return st, path, nil
}

// Save persists the context store to disk.
func (s *Store) Save() error {
	if strings.TrimSpace(s.path) == "" {
		path, err := resolveStorePath()
		if err != nil {
			return err
		}
		s.path = path
	}

	if err := fsutil.SafeMkdirAll(filepath.Dir(s.path), fsutil.WriteOptions{Perm: 0o700}); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	out, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return fsutil.SafeWriteFile(s.path, out, fsutil.WriteOptions{
		Perm:      0o600,
		Overwrite: true,
	})
}

func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}

func (s *Store) Names() []string {
	if len(s.Contexts) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.Contexts))
	for name := range s.Contexts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ResolveSelected identifies the selected context.
// Precedence is environment variable first, then active context in store.
func (s *Store) ResolveSelected() (name string, ctx *Context, exists bool, err error) {
	name = strings.TrimSpace(os.Getenv(env.Context.Name))
	source := "environment variable"
	if name == "" {
		name = strings.TrimSpace(s.Active)
		source = "active config"
	}
	if name == "" {
		return "", nil, false, nil
	}

	selected, ok := s.Contexts[name]
	if !ok {
		return "", nil, false, fmt.Errorf("%w: %q from %s (available: %s)", ErrContextNotFound, name, source, strings.Join(s.Names(), ", "))
	}

	return name, &selected, true, nil
}

// Root returns the trimmed project root for this context.
func (c Context) Root() string {
	return strings.TrimSpace(c.ProjectRoot)
}

// AbsPath resolves p against the context's project root.
func (c Context) AbsPath(p string) string {
	clean := strings.TrimSpace(p)
	if clean == "" {
		return ""
	}
	if filepath.IsAbs(clean) {
		return filepath.Clean(clean)
	}
	root := c.Root()
	if root == "" {
		return filepath.Clean(clean)
	}
	return filepath.Clean(filepath.Join(root, clean))
}
