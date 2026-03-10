package pack

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/samber/lo"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

// ErrEmptyRegistry is returned when a registry index contains no packs.
var ErrEmptyRegistry = errors.New("registry contains no packs")

//go:embed embedded/index.yaml
var embeddedRegistryFS embed.FS

// ControlRef describes a single control entry in the registry index.
type ControlRef struct {
	Path    string `yaml:"path"`
	Summary string `yaml:"summary"`
}

type packSpec struct {
	Description string   `yaml:"description"`
	Controls    []string `yaml:"controls"`
}

type registryIndex struct {
	Version  string                `yaml:"version"`
	Packs    map[string]packSpec   `yaml:"packs"`
	Controls map[string]ControlRef `yaml:"controls"`
}

// Pack describes a named control pack.
type Pack struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Controls    []string `json:"controls"`
}

// Registry holds pre-processed pack data. Use NewRegistry for testing
// or the package-level functions for production (backed by embedded data).
type Registry struct {
	version   string
	hash      kernel.Digest
	packs     map[string]Pack
	packNames []string
	// controls preserves the raw control metadata from the index.
	controls map[string]ControlRef
}

// NewRegistry parses YAML data into a Registry with all packs pre-sorted.
func NewRegistry(data []byte) (*Registry, error) {
	var idx registryIndex
	if err := yaml.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	if len(idx.Packs) == 0 {
		return nil, ErrEmptyRegistry
	}

	r := &Registry{
		version:   strings.TrimSpace(idx.Version),
		hash:      crypto.HashBytes(data),
		packs:     make(map[string]Pack, len(idx.Packs)),
		controls:  idx.Controls,
		packNames: make([]string, 0, len(idx.Packs)),
	}
	if r.controls == nil {
		r.controls = map[string]ControlRef{}
	}

	if err := r.loadPacks(idx.Packs); err != nil {
		return nil, err
	}
	slices.Sort(r.packNames)

	return r, nil
}

func (r *Registry) loadPacks(specs map[string]packSpec) error {
	for name, spec := range specs {
		ids := slices.Clone(spec.Controls)
		slices.Sort(ids)

		for _, id := range ids {
			if _, ok := r.controls[id]; !ok {
				return fmt.Errorf("pack %q: undefined control %q", name, id)
			}
		}

		r.packs[name] = Pack{
			Name:        name,
			Description: spec.Description,
			Controls:    ids,
		}
		r.packNames = append(r.packNames, name)
	}
	return nil
}

// ListPacks returns all available packs in stable name order.
func (r *Registry) ListPacks() []Pack {
	return lo.Map(r.packNames, func(name string, _ int) Pack { return clonePack(r.packs[name]) })
}

// PackNames returns all pack names in stable order.
func (r *Registry) PackNames() []string {
	return slices.Clone(r.packNames)
}

// LookupPack returns one pack by name.
func (r *Registry) LookupPack(name string) (Pack, bool) {
	p, ok := r.packs[strings.TrimSpace(name)]
	if !ok {
		return Pack{}, false
	}
	return clonePack(p), true
}

// ResolveEnabledPacks expands packs into de-duplicated, sorted control IDs.
func (r *Registry) ResolveEnabledPacks(names []string) ([]string, error) {
	seen := make(map[string]struct{})
	var ids []string
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		p, ok := r.packs[name]
		if !ok {
			return nil, fmt.Errorf("unknown control pack %q; run `stave packs list` to see available packs", name)
		}
		for _, id := range p.Controls {
			if _, dup := seen[id]; !dup {
				seen[id] = struct{}{}
				ids = append(ids, id)
			}
		}
	}
	slices.Sort(ids)
	return ids, nil
}

// Version returns the registry version string.
func (r *Registry) Version() string {
	return r.version
}

// Hash returns the SHA-256 hex digest of the raw registry bytes.
func (r *Registry) Hash() kernel.Digest {
	return r.hash
}

// ControlRefs returns the raw control metadata map.
func (r *Registry) ControlRefs() map[string]ControlRef {
	return maps.Clone(r.controls)
}

// VerifyNoOrphans checks fsys under root for YAML files not referenced by index metadata.
func (r *Registry) VerifyNoOrphans(fsys embed.FS, root string) ([]string, error) {
	root = path.Clean(strings.TrimSpace(root))
	referenced := make(map[string]struct{}, len(r.controls))

	for _, ref := range r.controls {
		referenced[normalizeControlFSPath(ref.Path)] = struct{}{}
	}

	var orphans []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		p = path.Clean(p)
		if !strings.HasSuffix(p, ".yaml") || path.Base(p) == "index.yaml" {
			return nil
		}

		if _, ok := referenced[p]; !ok {
			orphans = append(orphans, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(orphans)
	return orphans, nil
}

// --- Default embedded registry (package-level convenience API) ---

var (
	defaultOnce     sync.Once
	defaultRegistry *Registry
	defaultErr      error
)

func registry() (*Registry, error) {
	defaultOnce.Do(func() {
		var data []byte
		data, defaultErr = embeddedRegistryFS.ReadFile("embedded/index.yaml")
		if defaultErr != nil {
			defaultErr = fmt.Errorf("read embedded pack registry: %w", defaultErr)
			return
		}
		defaultRegistry, defaultErr = NewRegistry(data)
	})
	return defaultRegistry, defaultErr
}

func ensureDefault() error {
	_, err := registry()
	return err
}

// DefaultRegistry returns the embedded default pack registry singleton.
func DefaultRegistry() (*Registry, error) {
	return registry()
}

// ListPacks returns all available packs from the embedded registry.
func ListPacks() ([]Pack, error) {
	reg, err := registry()
	if err != nil {
		return nil, err
	}
	return reg.ListPacks(), nil
}

// PackNames returns all pack names from the embedded registry.
func PackNames() ([]string, error) {
	reg, err := registry()
	if err != nil {
		return nil, err
	}
	return reg.PackNames(), nil
}

// LookupPack returns one pack by name from the embedded registry.
func LookupPack(name string) (Pack, bool, error) {
	reg, err := registry()
	if err != nil {
		return Pack{}, false, err
	}
	p, ok := reg.LookupPack(name)
	return p, ok, nil
}

// ResolveEnabledPacks expands packs from the embedded registry.
func ResolveEnabledPacks(names []string) ([]string, error) {
	reg, err := registry()
	if err != nil {
		return nil, err
	}
	return reg.ResolveEnabledPacks(names)
}

// RegistryVersion returns the embedded pack registry version.
func RegistryVersion() (string, error) {
	reg, err := registry()
	if err != nil {
		return "", err
	}
	return reg.Version(), nil
}

// RegistryHash returns the SHA-256 hash of embedded index bytes.
func RegistryHash() (kernel.Digest, error) {
	reg, err := registry()
	if err != nil {
		return "", err
	}
	return reg.Hash(), nil
}

func clonePack(p Pack) Pack {
	out := p
	out.Controls = slices.Clone(p.Controls)
	return out
}
