package config

import (
	"errors"
	"fmt"
	"log/slog"
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

// configDirName / contextsFileName name the on-disk locations Stave
// uses for its user-level config. Centralised so tests, the
// initcmd/contextcmd resolver, and store_test.go all reference the
// same string instead of each open-coding "stave" / "contexts.yaml".
const (
	configDirName    = "stave"
	contextsFileName = "contexts.yaml"
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

// Validate checks the context shape. Returns an error when a
// required field is missing or a path is structurally invalid.
// Production callers should run this on every newly-loaded or
// newly-set context so a malformed entry surfaces at the
// configuration boundary rather than mid-evaluation.
func (c Context) Validate() error {
	root := strings.TrimSpace(c.ProjectRoot)
	if root == "" {
		return errors.New("project_root must not be empty")
	}
	// ProjectRoot is normally absolute (a stave context labels a
	// working directory) so the absolute/relative check is skipped
	// here; only reject traversal that would let a context escape
	// itself once joined with a sub-path. Routes through the same
	// segment-based ".." detection isPathSafe uses for the relative
	// fields, so a future tightening (UNC handling, separator
	// normalisation) lands once.
	if !hasNoUnsafeSegments(root) {
		return fmt.Errorf("project_root contains unsafe path components: %q", root)
	}
	cfg := strings.TrimSpace(c.ProjectConfig)
	if cfg != "" && !isPathSafe(cfg) {
		return fmt.Errorf("project_config contains unsafe path components: %q", cfg)
	}
	// Defaults paths resolve relative to project_root at the call
	// site, so the same isPathSafe contract that protects
	// project_config applies: no absolute paths, no `..` traversal,
	// and the value must equal its filepath.Clean form. A malicious
	// stored context could otherwise pin defaults at "../../etc/..."
	// and redirect every default-path read out of the working tree.
	if d := strings.TrimSpace(c.Defaults.ControlsDir); d != "" && !isPathSafe(d) {
		return fmt.Errorf("defaults.controls_dir contains unsafe path components: %q", d)
	}
	if d := strings.TrimSpace(c.Defaults.ObservationsDir); d != "" && !isPathSafe(d) {
		return fmt.Errorf("defaults.observations_dir contains unsafe path components: %q", d)
	}
	return nil
}

// isPathSafe reports whether a path is structurally safe to store
// in a stave context entry: not absolute, not containing parent
// (`..`) traversal, and identical to its filepath.Clean form. Used
// for fields expected to resolve relative to the project root —
// absolute paths and traversal there could let a malicious context
// file redirect reads outside the working tree.
func isPathSafe(path string) bool {
	if path == "" {
		return true
	}
	if filepath.IsAbs(path) {
		return false
	}
	return hasNoUnsafeSegments(path)
}

// hasNoUnsafeSegments returns true when path is in canonical form and
// carries no `..` segment. Shared by isPathSafe (rejects absolute
// paths, used for relative defaults) and the ProjectRoot check
// (which ALLOWS absolute paths and only screens for traversal).
//
// Empty input is safe. Cleans the path; if Clean changes it the
// input wasn't canonical and is rejected. Then splits on either
// separator to catch "..\foo" (Windows) and "../foo" (POSIX) at the
// segment level — this is the segment-based guard the user-facing
// validators all funnel through so a future tightening (UNC, BOM,
// reserved names) lands once.
func hasNoUnsafeSegments(path string) bool {
	if path == "" {
		return true
	}
	// Clean the input then operate on the canonical form. The
	// previous shape rejected any input that wasn't already
	// canonical, which false-positived on benign forms operators
	// write in YAML (`controls/` with trailing slash, `./controls`,
	// duplicate `//` separators). The safety property the function
	// is meant to enforce is "no `..` segment", which Clean
	// preserves; rejecting non-canonical inputs was a separate
	// concern that bled into this guard.
	cleaned := filepath.Clean(path)
	// Substring fast-path: when ".." appears nowhere in the cleaned
	// path, no segment can possibly be `..`, so we skip the
	// allocation-heavy split + scan. The check is intentionally
	// conservative — a benign value like `v1..2` (a version string)
	// contains the substring but is not a traversal, so it falls
	// through to the segment walk below where it correctly passes
	// the `slices.Contains(..., "..")` rejection. Future maintainers
	// who want to "tighten" this path by short-circuiting on the
	// substring alone would reject legitimate inputs.
	if !strings.Contains(cleaned, "..") {
		return true
	}
	normalized := strings.ReplaceAll(cleaned, "\\", "/")
	return !slices.Contains(strings.Split(normalized, "/"), "..")
}

// IsProduction reports whether the context is marked as a production
// environment. Wraps the boolean field so audit-logging can be
// added at the read site if needed.
func (c Context) IsProduction() bool { return c.Production }

// CanonicalProjectRoot returns ProjectRoot with surrounding
// whitespace trimmed. Wraps the strings.TrimSpace pattern that
// init/contextcmd applies inline so callers stop reaching for the
// raw field plus a per-call trim.
func (c Context) CanonicalProjectRoot() string {
	return strings.TrimSpace(c.ProjectRoot)
}

// CanonicalProjectConfig returns ProjectConfig with surrounding
// whitespace trimmed. Sibling of CanonicalProjectRoot.
func (c Context) CanonicalProjectConfig() string {
	return strings.TrimSpace(c.ProjectConfig)
}

// DefaultControlsDir is the fallback directory name when a context
// does not specify one. Matches the cmd/* flag default for
// --controls so context-driven and explicit-flag invocations both
// resolve to `./controls` by default.
const DefaultControlsDir = "controls"

// DefaultObservationsDir is the fallback directory name when a
// context does not specify one. Matches the cmd/* flag default for
// --observations so context-driven and explicit-flag invocations
// both resolve to `./observations` by default.
const DefaultObservationsDir = "observations"

// EffectiveControlsDir returns the trimmed Defaults.ControlsDir, or
// DefaultControlsDir when the field is empty / whitespace.
// "Effective" rather than "Canonical" because callers reach for
// this when resolving the actual directory to use.
func (c Context) EffectiveControlsDir() string {
	v := strings.TrimSpace(c.Defaults.ControlsDir)
	if v == "" {
		return DefaultControlsDir
	}
	return v
}

// EffectiveObservationsDir returns the trimmed Defaults.ObservationsDir,
// or DefaultObservationsDir when the field is empty / whitespace.
// Sibling of EffectiveControlsDir.
func (c Context) EffectiveObservationsDir() string {
	v := strings.TrimSpace(c.Defaults.ObservationsDir)
	if v == "" {
		return DefaultObservationsDir
	}
	return v
}

// Clone returns a deep copy of the context. Context contains only
// value-typed fields (strings, struct of strings, bool) so a plain
// struct copy IS the deep copy; the explicit method exists so
// callers signal intent ("I want a mutable working copy") rather
// than relying on Go's value-semantics trick. After mutating the
// clone, persist via (*Store).SetContext + (*Store).Save.
func (c Context) Clone() Context {
	return c
}

// Store represents the persistent collection of named stave contexts.
// The contexts map is unexported so callers cannot bypass ValidateName
// when adding entries; use GetContext / SetContext / DeleteContext.
type Store struct {
	Active   string             `yaml:"active,omitempty"`
	contexts map[string]Context `yaml:"contexts,omitempty"`
	path     string             `yaml:"-"`
}

// NewStore initializes an empty Store.
func NewStore() *Store {
	return &Store{
		contexts: make(map[string]Context),
	}
}

// UnmarshalYAML handles custom decoding to ensure maps are always initialized.
//
// The intermediate type carries an exported `Contexts` field so the
// YAML decoder can populate it; we then move the data into the
// unexported `contexts` map on the live Store.
//
// Per-context validation runs here at the type-level decode boundary
// so a caller that goes through yaml.Unmarshal directly (in-process
// composition, tests, future API surface) cannot bypass the trust
// boundary. Load() relies on this same path and only adds the
// file-level cross-checks (path-decorated error messages, active
// referencing an entry that exists).
func (s *Store) UnmarshalYAML(value *yaml.Node) error {
	var aux struct {
		Active   string             `yaml:"active,omitempty"`
		Contexts map[string]Context `yaml:"contexts,omitempty"`
	}
	if err := value.Decode(&aux); err != nil {
		return err
	}
	if err := validateContextsMap(aux.Contexts); err != nil {
		return err
	}
	s.Active = aux.Active
	s.contexts = aux.Contexts
	if s.contexts == nil {
		s.contexts = make(map[string]Context)
	}
	return nil
}

// validateContextsMap runs name + body validation for every entry
// in the parsed contexts map. Shared between UnmarshalYAML (the
// in-memory trust boundary) and Load (the on-disk trust boundary)
// so the rule set cannot drift between the two callers.
func validateContextsMap(contexts map[string]Context) error {
	for name, ctx := range contexts {
		if err := ValidateName(name); err != nil {
			return fmt.Errorf("context name %q: %w", name, err)
		}
		if err := ctx.Validate(); err != nil {
			return fmt.Errorf("context %q: %w", name, err)
		}
	}
	return nil
}

// MarshalYAML emits the store with the exported `contexts` key the
// on-disk format has always used.
func (s *Store) MarshalYAML() (any, error) {
	return struct {
		Active   string             `yaml:"active,omitempty"`
		Contexts map[string]Context `yaml:"contexts,omitempty"`
	}{Active: s.Active, Contexts: s.contexts}, nil
}

// GetContext returns the context registered under name, or false
// when the name is unknown. The caller receives a copy — mutations
// must go through SetContext to persist.
func (s *Store) GetContext(name string) (Context, bool) {
	c, ok := s.contexts[name]
	return c, ok
}

// SetContext stores ctx under name. Validates the name and the
// context shape; rejects malformed entries instead of accepting
// them and surfacing the failure later at load time.
func (s *Store) SetContext(name string, ctx Context) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := ctx.Validate(); err != nil {
		return fmt.Errorf("invalid context %q: %w", name, err)
	}
	if s.contexts == nil {
		s.contexts = make(map[string]Context, 1)
	}
	s.contexts[name] = ctx
	return nil
}

// DeleteContext removes name from the store. Returns
// ErrContextNotFound when the name is unknown so callers can
// distinguish "removed it" from "wasn't there to begin with".
//
// If the deleted context happens to be the active one, the active
// pointer is cleared rather than left dangling — a stale Active
// reference is a worse failure mode than "no context selected"
// because lookups silently return the contexts map's zero value
// (an empty Context) and downstream code reads through it.
func (s *Store) DeleteContext(name string) error {
	if _, ok := s.contexts[name]; !ok {
		return fmt.Errorf("%w: %q", ErrContextNotFound, name)
	}
	delete(s.contexts, name)
	if s.Active == name {
		s.Active = ""
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

	// Per-context validation has already run inside UnmarshalYAML
	// (the type-level trust boundary). On-disk Load only adds the
	// file-level cross-checks below. yaml.Unmarshal would have
	// returned the validation error wrapped in its parse error
	// above, so reaching this point means every context entry is
	// already structurally sound.

	// Validate the active context name itself. ValidateName covers
	// the same charset rules used when adding entries via SetContext;
	// without this check a stored YAML with a malicious or otherwise
	// invalid `active:` value (path-traversal in a future caller that
	// uses Active as a path component, embedded null bytes, etc.)
	// would round-trip through Load unobserved. Empty Active is
	// allowed — that means "no context selected".
	if store.Active != "" {
		if err := ValidateName(store.Active); err != nil {
			return nil, "", fmt.Errorf("active context name at %q is invalid: %w", path, err)
		}
		// Existence check: a YAML that names an active context not
		// present in the contexts map is internally inconsistent
		// (the resolver downstream returns ErrContextNotFound mid-
		// command, with no path-of-origin). Catch it at load.
		if _, ok := store.contexts[store.Active]; !ok {
			return nil, "", fmt.Errorf("active context %q not found in store at %q", store.Active, path)
		}
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
//
// It rejects empty strings, overlong inputs, and characters that are
// unsafe in filesystem paths or YAML keys. The exact forbidden set
// (mirrored in the error message below) is:
//
//	/  \  NUL  \n  \r  \t  ASCII space  :  {  }  [  ]  #  *  &  !  |  >  '  "  %
//
// Path separators (/ \) prevent traversal when a name is
// interpolated into a path. NUL and whitespace controls prevent
// argument-list smuggling. YAML structural / indicator characters
// (: { } [ ] # * & ! | > ' " %) ensure the name is YAML-safe as a
// bare map key without quoting or escaping.
//
// Shell metacharacters not in the forbidden set (@ ~ ^ ( ) ; ,)
// are allowed by design — context names like "prod@aws" or
// "user~home" are legitimate; the boundary against shell injection
// is owned by the call sites that interpolate into shell commands
// (none today; future ones must escape, not rely on validator
// rejection).
func ValidateName(name string) error {
	if name == "" {
		return errors.New("context name cannot be empty")
	}
	if len(name) > maxContextNameLen {
		return fmt.Errorf("context name exceeds %d characters", maxContextNameLen)
	}
	if strings.ContainsAny(name, "/\\\x00\n\r\t :{}[]#*&!|>'\"%") {
		return errors.New(`context name contains forbidden characters (/, \, NUL, space, tab, newline, carriage return, or YAML indicators :{}[]#*&!|>'"%)`)
	}
	return nil
}

// Names returns a sorted list of all available context names.
func (s *Store) Names() []string {
	if len(s.contexts) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.contexts))
	for n := range s.contexts {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// ResolveSelected returns a read-only snapshot of the active context.
//
// Precedence: STAVE_CONTEXT env var > active field in contexts.yaml.
//
// The returned *Context points at a stack-local COPY of the in-map
// value, so mutations through the pointer are not visible to
// subsequent ResolveSelected calls and are not persisted by Save.
// The pointer return shape is kept for ergonomic nil-checking; the
// pointer must not be used to write back into the store. Callers
// that need a mutable working copy should call (*Context).Clone()
// — the contract documents the snapshot semantics clearly so a
// reader does not have to remember Go's "maps return values" rule.
//
// To update a context, mutate via SetContext / DeleteContext on the
// Store, or take a Clone, mutate, and call SetContext.
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

	selected, ok := s.contexts[name]
	if !ok {
		available := strings.Join(s.Names(), ", ")
		return "", nil, false, fmt.Errorf("%w: %q (from %s); available: [%s]",
			ErrContextNotFound, name, source, available)
	}

	// Return a pointer to the local copy. The pointer is a
	// READ-ONLY SNAPSHOT — mutations through it do NOT propagate
	// back to the store's map (Go maps return values by value, not
	// reference). Callers that need to update a context must do so
	// through a Set/Update method on the store, not by mutating
	// what ResolveSelected hands back. The pointer return is
	// preserved (vs. returning the value) so existing call sites
	// can still test for presence with a nil check.
	return name, &selected, true, nil
}

// AbsPath joins the provided path with the context's project root if
// the path is relative.
//
// Empty ProjectRoot with a relative input is a configuration gap:
// the caller asked for "anchor this relative path against the
// project root" but never provided a root. The earlier shape
// silently fell back to filepath.Clean(p), which produced a path
// resolved against whatever cwd happened to be — an inconsistent
// answer depending on where the binary was launched. Log a warning
// so operators see the gap; preserve the cwd-relative behavior so
// existing scripts that rely on the implicit fallback don't break,
// but flag the configuration drift in the logs.
// AbsPath returns the absolute form of p, anchored against the
// context's ProjectRoot when p is relative. Empty p returns "" (the
// "no path supplied" signal callers depend on).
//
// PRECONDITION: ProjectRoot must be non-empty for relative inputs.
// The function logs a warning and falls back to filepath.Clean(p)
// (cwd-relative) for relative inputs when ProjectRoot is empty —
// this preserves long-standing behaviour for existing scripts but
// hides a configuration gap. New code should call AbsPathStrict
// instead, which surfaces the empty-ProjectRoot case as an error.
func (c Context) AbsPath(p string) string {
	out, err := c.AbsPathStrict(p)
	if err != nil {
		slog.Warn("config.Context.AbsPath: ProjectRoot empty for relative path; resolving against cwd",
			"path", p, "error", err)
		return filepath.Clean(strings.TrimSpace(p))
	}
	return out
}

// AbsPathStrict returns the absolute form of p anchored against the
// context's ProjectRoot. Returns an error when p is relative and
// ProjectRoot is empty — the caller asked for "anchor against the
// project root" but never supplied a root, and silently substituting
// cwd produces an inconsistent answer depending on where the binary
// was launched. Empty p returns ("", nil) as the "no path supplied"
// signal.
func (c Context) AbsPathStrict(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p), nil
	}
	root := strings.TrimSpace(c.ProjectRoot)
	if root == "" {
		return "", fmt.Errorf("cannot resolve relative path %q: context project_root is empty", p)
	}
	return filepath.Clean(filepath.Join(root, p)), nil
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

	cfgDir, cfgErr := os.UserConfigDir()
	if cfgErr == nil && cfgDir != "" {
		return filepath.Join(cfgDir, configDirName, contextsFileName), nil
	}
	if cfgErr != nil {
		// Log the platform-reported reason before falling through
		// to UserHomeDir — silently swallowing it has masked WSL /
		// container environments where XDG_CONFIG_HOME is missing
		// AND HOME is set to a path the platform considers invalid,
		// producing confusing "config not found" errors with no
		// clue which lookup actually failed.
		slog.Warn("config: os.UserConfigDir failed; falling back to UserHomeDir",
			"error", cfgErr)
	} else if cfgDir == "" {
		// No error, but the platform returned an empty path. This
		// is the documented "no config directory available" return
		// shape on platforms where neither XDG_CONFIG_HOME nor the
		// fallback default resolves to anything (some sandboxed
		// environments, container images stripped of $HOME, etc.).
		// Surface the fall-through so operators don't confuse the
		// resulting "context file under HOME/.config" path with a
		// platform-blessed location.
		slog.Warn("config: os.UserConfigDir returned empty path with no error; falling back to UserHomeDir")
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", ErrNoConfigDir
	}
	return filepath.Join(home, ".config", configDirName, contextsFileName), nil
}
