package pack

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/core/kernel"
)

// hashBytes returns the SHA-256 hex digest of data.
// Inlined from internal/platform/crypto so the builtin pack registry
// (which is closer to the domain layer than platform) does not depend
// on platform/crypto for what amounts to two stdlib calls.
func hashBytes(data []byte) kernel.Digest {
	sum := sha256.Sum256(data)
	return kernel.Digest(hex.EncodeToString(sum[:]))
}

// hashDelimited returns the SHA-256 hex digest of parts joined by sep.
// Each part is followed by sep so the encoding is reversible at the
// digest boundary (no two distinct part lists collide on this digest
// for any single-byte sep).
func hashDelimited(parts []string, sep byte) kernel.Digest {
	h := sha256.New()
	var sepBuf [1]byte
	sepBuf[0] = sep
	for _, p := range parts {
		_, _ = io.WriteString(h, p)
		_, _ = h.Write(sepBuf[:])
	}
	return kernel.Digest(hex.EncodeToString(h.Sum(nil)))
}

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
	controls map[kernel.ControlID]ControlRef
}

// testRegistryIndex is the legacy inline format used by unit tests.
// YAML keys are still parsed as strings; conversion to kernel.ControlID
// happens once after unmarshal.
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
		hash:      hashBytes(data),
		packs:     make(map[string]Pack, len(idx.Packs)),
		controls:  make(map[kernel.ControlID]ControlRef, len(idx.Controls)),
		packNames: make([]string, 0, len(idx.Packs)),
	}
	for k, v := range idx.Controls {
		r.controls[kernel.ControlID(k)] = v
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

// loadPacks resolves the parsed pack specs into the registry's packs
// map. Every control ID listed in a pack must have a metadata entry
// in r.controls — PopulateControlRefs is the only path that fills
// that map and must run before loadPacks.
func (r *Index) loadPacks(specs map[string]packSpec) error {
	if r.controls == nil {
		return errors.New("loadPacks: controls metadata not populated; call PopulateControlRefs first")
	}
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
func (r *Index) ControlRefs() map[kernel.ControlID]ControlRef {
	return maps.Clone(r.controls)
}

// VerifyNoOrphans checks fsys under root for YAML files not referenced by index metadata.
func (r *Index) VerifyNoOrphans(fsys embed.FS, root string) ([]string, error) {
	referenced := make(map[string]struct{}, len(r.controls))
	for _, ref := range r.controls {
		referenced[normalizeControlFSPath(ref.Path)] = struct{}{}
	}

	var orphans []string
	err := walkControlYAMLs(fsys, root, func(p string, _ fs.DirEntry) error {
		if path.Base(p) == "index.yaml" {
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
		packs:     make(map[string]Pack, len(manifest.Packs)),
		controls:  map[kernel.ControlID]ControlRef{},
		packNames: make([]string, 0, len(manifest.Packs)),
	}

	// Derive control metadata from embedded control YAMLs.
	if err := r.PopulateControlRefs(controldata.FS, "embedded"); err != nil {
		return nil, fmt.Errorf("derive control refs: %w", err)
	}

	// Load each pack file from the manifest, in manifest order so the
	// registry-level hash is reproducible. Hashing only index.yaml
	// previously made tampering with a pack's control list invisible
	// to integrity checks; fold the pack file bytes into the hash so
	// any byte-level change to a pack invalidates the registry hash.
	hashParts := make([]string, 0, 1+2*len(manifest.Packs))
	hashParts = append(hashParts, string(data))
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
		hashParts = append(hashParts, ref.Path, string(packData))
	}
	r.hash = hashDelimited(hashParts, 0x00)

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
