package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/env"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var (
	// ErrContextNotFound is returned when a requested context name doesn't exist.
	ErrContextNotFound = errors.New("context not found")

	// ErrNoConfigDir is returned when standard system config locations cannot be found.
	ErrNoConfigDir = errors.New("could not resolve a config directory or user home")
)

type Defaults struct {
	ControlsDir     string `yaml:"controls_dir,omitempty"`
	ObservationsDir string `yaml:"observations_dir,omitempty"`
}

type Context struct {
	ProjectRoot   string   `yaml:"project_root"`
	ProjectConfig string   `yaml:"project_config,omitempty"`
	Defaults      Defaults `yaml:"defaults,omitempty"`
}

// Store represents the persistent collection of named stave contexts.
type Store struct {
	Active   string             `yaml:"active,omitempty"`
	Contexts map[string]Context `yaml:"contexts,omitempty"`
	path     string             `yaml:"-"`
}

// NewStore initializes an empty Store.
func NewStore() *Store {
	return &Store{
		Contexts: make(map[string]Context),
	}
}

// UnmarshalYAML handles custom decoding to ensure maps are always initialized.
func (s *Store) UnmarshalYAML(value *yaml.Node) error {
	type rawStore Store
	var aux rawStore
	if err := value.Decode(&aux); err != nil {
		return err
	}
	*s = Store(aux)
	if s.Contexts == nil {
		s.Contexts = make(map[string]Context)
	}
	return nil
}

// Load reads the context store from the standard or overridden filesystem path.
func Load() (*Store, string, error) {
	path, err := resolveStorePath()
	if err != nil {
		return nil, "", err
	}

	store := NewStore()
	store.path = path

	// #nosec G304 -- path comes from a local config location or explicit STAVE_CONTEXTS_FILE override.
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, path, nil
		}
		return nil, "", fmt.Errorf("failed to read context file: %w", err)
	}

	if err := yaml.Unmarshal(data, store); err != nil {
		return nil, "", fmt.Errorf("failed to parse context YAML at %q: %w", path, err)
	}

	return store, path, nil
}

// Save persists the current state of the store to disk.
func (s *Store) Save() error {
	if s.path == "" {
		p, err := resolveStorePath()
		if err != nil {
			return err
		}
		s.path = p
	}

	dir := filepath.Dir(s.path)
	if err := fsutil.SafeMkdirAll(dir, fsutil.WriteOptions{Perm: 0o700}); err != nil {
		return fmt.Errorf("failed to create config directory %q: %w", dir, err)
	}

	out, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to marshal context config: %w", err)
	}

	return fsutil.SafeWriteFile(s.path, out, fsutil.WriteOptions{
		Perm:      0o600,
		Overwrite: true,
	})
}

// NormalizeName trims whitespace from a context name.
func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}

// Names returns a sorted list of all available context names.
func (s *Store) Names() []string {
	if len(s.Contexts) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Contexts))
	for n := range s.Contexts {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// ResolveSelected identifies which context is currently active.
// Precedence: STAVE_CONTEXT env var > active field in contexts.yaml.
func (s *Store) ResolveSelected() (string, *Context, bool, error) {
	name := strings.TrimSpace(os.Getenv(env.Context.Name))
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
		available := strings.Join(s.Names(), ", ")
		return "", nil, false, fmt.Errorf("%w: %q (from %s); available: [%s]",
			ErrContextNotFound, name, source, available)
	}

	return name, &selected, true, nil
}

// AbsPath joins the provided path with the context's project root if the path is relative.
func (c Context) AbsPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}

	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}

	root := strings.TrimSpace(c.ProjectRoot)
	if root == "" {
		return filepath.Clean(p)
	}

	return filepath.Clean(filepath.Join(root, p))
}

// resolveStorePath determines where the context file should be stored.
func resolveStorePath() (string, error) {
	if v := strings.TrimSpace(os.Getenv(env.ContextsFile.Name)); v != "" {
		return v, nil
	}

	if cfgDir, err := os.UserConfigDir(); err == nil && cfgDir != "" {
		return filepath.Join(cfgDir, "stave", "contexts.yaml"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", ErrNoConfigDir
	}
	return filepath.Join(home, ".config", "stave", "contexts.yaml"), nil
}
