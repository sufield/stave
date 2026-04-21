package pack

import (
	"embed"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

//go:embed embedded/index.yaml embedded/packs/*.yaml
var embeddedRegistryFS embed.FS

// ControlRef describes a single control entry in the registry index.
type ControlRef struct {
	Path    string `yaml:"path"`
	Summary string `yaml:"summary"`
}

type packSpec struct {
	ID          string             `yaml:"id"`
	Description string             `yaml:"description"`
	Controls    []kernel.ControlID `yaml:"controls"`
}

// packRef is a manifest entry pointing to a pack file.
type packRef struct {
	ID   string `yaml:"id"`
	Path string `yaml:"path"`
}

type registryIndex struct {
	Version string    `yaml:"version"`
	Packs   []packRef `yaml:"packs"`
}

// Pack describes a named control pack.
type Pack struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Controls    []kernel.ControlID `json:"controls"`
}

// Index holds pre-processed pack data. Use NewIndex for testing
// or the package-level functions for production (backed by embedded data).
type Index struct {
	version   string
	hash      kernel.Digest
	packs     map[string]Pack
	packNames []string
	// controls preserves the raw control metadata from the index.
	controls map[string]ControlRef
}

// testRegistryIndex is the legacy inline format used by unit tests.
type testRegistryIndex struct {
	Version  string                `yaml:"version"`
	Packs    map[string]packSpec   `yaml:"packs"`
	Controls map[string]ControlRef `yaml:"controls"`
}

// NewIndex parses inline YAML data into an Index. This supports the legacy
// format where packs and controls are defined inline — used by unit tests.
// Production code uses NewEmbeddedRegistry which reads per-pack files.
func NewIndex(data []byte) (*Index, error) {
	var idx testRegistryIndex
	if err := yaml.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	r := &Index{
		version:   strings.TrimSpace(idx.Version),
		hash:      crypto.HashBytes(data),
		packs:     make(map[string]Pack, len(idx.Packs)),
		controls:  idx.Controls,
		packNames: make([]string, 0, len(idx.Packs)),
	}
	if r.controls == nil {
		r.controls = map[string]ControlRef{}
	}

	specs := make(map[string]packSpec, len(idx.Packs))
	for name, spec := range idx.Packs {
		spec.ID = name
		specs[name] = spec
	}
	if err := r.loadPacks(specs); err != nil {
		return nil, err
	}
	slices.Sort(r.packNames)

	return r, nil
}

// PopulateControlRefs derives the controls metadata map from the embedded
// filesystem, replacing any hand-maintained controls: section from the YAML.
// This must be called after NewIndex and before ValidateStrict.
func (r *Index) PopulateControlRefs(fsys embed.FS, root string) error {
	refs, err := DeriveControlRefs(fsys, root)
	if err != nil {
		return err
	}
	r.controls = refs
	return nil
}

func (r *Index) loadPacks(specs map[string]packSpec) error {
	for name, spec := range specs {
		ids := slices.Clone(spec.Controls)
		slices.Sort(ids)

		// When controls: map is populated (backward compat), validate
		// that every pack control ID has a metadata entry.
		if len(r.controls) > 0 {
			for _, id := range ids {
				if _, ok := r.controls[string(id)]; !ok {
					return fmt.Errorf("pack %q: undefined control %q", name, id)
				}
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
func (r *Index) ListPacks() []Pack {
	out := make([]Pack, len(r.packNames))
	for i, name := range r.packNames {
		out[i] = clonePack(r.packs[name])
	}
	return out
}

// PackNames returns all pack names in stable order.
func (r *Index) PackNames() []string {
	return slices.Clone(r.packNames)
}

// LookupPack returns one pack by name.
func (r *Index) LookupPack(name string) (Pack, bool) {
	p, ok := r.packs[strings.TrimSpace(name)]
	if !ok {
		return Pack{}, false
	}
	return clonePack(p), true
}

// ResolveEnabledPacks expands packs into de-duplicated, sorted control IDs.
func (r *Index) ResolveEnabledPacks(names []string) ([]kernel.ControlID, error) {
	seen := make(map[kernel.ControlID]struct{})
	var ids []kernel.ControlID
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
func (r *Index) Version() string {
	return r.version
}

// Hash returns the SHA-256 hex digest of the raw registry bytes.
func (r *Index) Hash() kernel.Digest {
	return r.hash
}

// RegistryVersion returns the version string. Satisfies appcontracts.PackRegistry.
func (r *Index) RegistryVersion() (string, error) {
	return r.version, nil
}

// RegistryHash returns the hash as a string. Satisfies appcontracts.PackRegistry.
func (r *Index) RegistryHash() (string, error) {
	return string(r.hash), nil
}

// ControlRefs returns the raw control metadata map.
func (r *Index) ControlRefs() map[string]ControlRef {
	return maps.Clone(r.controls)
}

// VerifyNoOrphans checks fsys under root for YAML files not referenced by index metadata.
func (r *Index) VerifyNoOrphans(fsys embed.FS, root string) ([]string, error) {
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
			name := d.Name()
			if p != root && (strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
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

// NewEmbeddedRegistry creates a registry from the bundled manifest and
// per-pack YAML files. Control metadata is derived from the embedded
// control YAML files.
func NewEmbeddedRegistry() (*Index, error) {
	data, err := embeddedRegistryFS.ReadFile("embedded/index.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded pack registry: %w", err)
	}

	var manifest registryIndex
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse registry manifest: %w", err)
	}

	r := &Index{
		version:   strings.TrimSpace(manifest.Version),
		hash:      crypto.HashBytes(data),
		packs:     make(map[string]Pack, len(manifest.Packs)),
		controls:  map[string]ControlRef{},
		packNames: make([]string, 0, len(manifest.Packs)),
	}

	// Derive control metadata from embedded control YAMLs.
	if err := r.PopulateControlRefs(controldata.FS, "embedded"); err != nil {
		return nil, fmt.Errorf("derive control refs: %w", err)
	}

	// Load each pack file from the manifest.
	specs := make(map[string]packSpec, len(manifest.Packs))
	for _, ref := range manifest.Packs {
		packData, readErr := embeddedRegistryFS.ReadFile("embedded/" + ref.Path)
		if readErr != nil {
			return nil, fmt.Errorf("read pack %q: %w", ref.ID, readErr)
		}
		var spec packSpec
		if yamlErr := yaml.Unmarshal(packData, &spec); yamlErr != nil {
			return nil, fmt.Errorf("parse pack %q: %w", ref.ID, yamlErr)
		}
		if spec.ID == "" {
			spec.ID = ref.ID
		}
		specs[spec.ID] = spec
	}

	if err := r.loadPacks(specs); err != nil {
		return nil, err
	}
	slices.Sort(r.packNames)

	return r, nil
}

func clonePack(p Pack) Pack {
	out := p
	out.Controls = slices.Clone(p.Controls)
	return out
}
