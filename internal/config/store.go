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

// Defaults holds the default directory paths for a context.
type Defaults struct {
	ControlsDir     string `yaml:"controls_dir,omitempty"`
	ObservationsDir string `yaml:"observations_dir,omitempty"`
}

// Context holds the configuration for a named project context.
type Context struct {
	ProjectRoot   string   `yaml:"project_root"`
	ProjectConfig string   `yaml:"project_config,omitempty"`
	Defaults      Defaults `yaml:"defaults,omitempty"`
	Production    bool     `yaml:"production,omitempty"`
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

// NormalizeName trims whitespace from a context name. The result is not
// guaranteed to be a valid context name — callers that persist the value
// should also call ValidateName to reject empty, overlong, or
// path-unsafe inputs.
func NormalizeName(name string) string {
	return strings.TrimSpace(name)
}

// maxContextNameLen caps the persisted name length. Long enough for
// "team-environment-purpose" labels; short enough that filesystem paths
// derived from the name stay well under typical limits.
const maxContextNameLen = 100

// ValidateName checks that a normalized context name is well-formed.
// It rejects empty strings, overlong inputs, and characters that are
// unsafe in filesystem paths or YAML keys. The forbidden set includes
// path separators, control bytes, and YAML structural/indicator
// characters — a name persisted as a YAML map key must not require
// quoting or escaping, and a name interpolated into a filesystem path
// must not let an attacker traverse, glob, or alias.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("context name cannot be empty")
	}
	if len(name) > maxContextNameLen {
		return fmt.Errorf("context name exceeds %d characters", maxContextNameLen)
	}
	if strings.ContainsAny(name, "/\\\x00\n\r\t:{}[]#*&!|>'\"%") {
		return errors.New(`context name contains forbidden characters (/, \, NUL, whitespace control, or YAML indicators :{}[]#*&!|>'"%)`)
	}
	return nil
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
//
// The returned *Context points at a stack-local COPY of the in-map value,
// so mutations through the pointer are not visible to subsequent
// ResolveSelected calls and are not persisted by Save. To update a
// context, modify s.Contexts[name] directly and call Save.
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
// When STAVE_CONTEXTS_FILE is set, the path is canonicalized
// (filepath.Clean collapses traversal sequences like "../") and
// resolved against the working directory if relative — both steps
// neutralize attempts to read or write outside the intended config
// scope by setting the env var to a constructed path.
func resolveStorePath() (string, error) {
	if v := strings.TrimSpace(os.Getenv(env.ContextsFile.Name)); v != "" {
		cleaned := filepath.Clean(v)
		if !filepath.IsAbs(cleaned) {
			cwd, err := os.Getwd()
			if err != nil {
				return "", fmt.Errorf("resolve %s: cwd unavailable: %w", env.ContextsFile.Name, err)
			}
			cleaned = filepath.Clean(filepath.Join(cwd, cleaned))
		}
		return cleaned, nil
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
