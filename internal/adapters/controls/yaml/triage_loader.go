package yaml

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	yamlv3 "gopkg.in/yaml.v3"
)

// TriageDir is the directory name for triage metadata within a
// control catalog root. It is _-prefixed so the control scanner
// skips it during recursive YAML discovery.
const TriageDir = "_triage"

type yamlTriageOverride struct {
	Control   string `yaml:"control"`
	Defect    string `yaml:"defect"`
	Infection string `yaml:"infection"`
	Failure   string `yaml:"failure"`
}

type yamlTriageFamily struct {
	Family    string `yaml:"family"`
	Infection string `yaml:"infection"`
	Failure   string `yaml:"failure"`
}

// TriageProse holds the three optional prose fields for a finding's
// defect/infection/failure triage chain.
type TriageProse struct {
	Defect    string
	Infection string
	Failure   string
}

type familyEntry struct {
	prefix string
	prose  TriageProse
}

// TriageIndex holds per-control overrides and family-level templates
// loaded from the _triage/ directory.
type TriageIndex struct {
	overrides map[kernel.ControlID]TriageProse
	families  []familyEntry // sorted longest-prefix-first
}

// Resolve returns the triage prose for a control, applying the
// inheritance chain: per-control override > family template.
// Each field is resolved independently — a control can have an
// override for defect but inherit infection from the family.
func (idx *TriageIndex) Resolve(id kernel.ControlID) TriageProse {
	var result TriageProse

	// Start with family template (base layer).
	sid := string(id)
	for _, f := range idx.families {
		if strings.HasPrefix(sid, f.prefix+".") {
			result = f.prose
			break
		}
	}

	// Override with per-control values (per-field granularity).
	if ov, ok := idx.overrides[id]; ok {
		if ov.Defect != "" {
			result.Defect = ov.Defect
		}
		if ov.Infection != "" {
			result.Infection = ov.Infection
		}
		if ov.Failure != "" {
			result.Failure = ov.Failure
		}
	}

	return result
}

// LoadTriageIndex reads triage overrides and family templates from
// dir/_triage/. Returns nil, nil if the _triage/ directory does not
// exist (matching the LoadChains pattern for optional directories).
func LoadTriageIndex(dir string) (*TriageIndex, error) {
	triagePath := filepath.Join(dir, TriageDir)
	if _, err := os.Stat(triagePath); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return LoadTriageIndexFS(os.DirFS(triagePath), ".")
}

// LoadTriageIndexFS reads triage data from an fs.FS rooted at the
// _triage/ directory. This variant supports both OS directories and
// embed.FS for the builtin control store.
func LoadTriageIndexFS(fsys fs.FS, root string) (*TriageIndex, error) {
	idx := &TriageIndex{
		overrides: make(map[kernel.ControlID]TriageProse),
	}

	if err := loadOverridesFS(fsys, filepath.Join(root, "overrides"), idx); err != nil {
		return nil, fmt.Errorf("loading triage overrides: %w", err)
	}

	if err := loadFamiliesFS(fsys, filepath.Join(root, "families"), idx); err != nil {
		return nil, fmt.Errorf("loading triage families: %w", err)
	}

	// Sort families longest-prefix-first for deterministic matching.
	slices.SortFunc(idx.families, func(a, b familyEntry) int {
		return cmp.Compare(len(b.prefix), len(a.prefix))
	})

	return idx, nil
}

func loadOverridesFS(fsys fs.FS, dir string, idx *TriageIndex) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		// errors.Is(err, fs.ErrNotExist) covers os.PathError, embed.FS's
		// internal error types, and any future filesystem implementation
		// that wraps the canonical sentinel. The earlier double-check
		// (os.IsNotExist + errors.As to *fs.PathError) was the
		// pre-Go-1.13 spelling; consolidating to the modern form
		// avoids drift if a new fs.FS implementation introduces a
		// different error type.
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("read override %q: %w", path, readErr)
		}

		var ov yamlTriageOverride
		if unmarshalErr := yamlv3.Unmarshal(data, &ov); unmarshalErr != nil {
			return fmt.Errorf("parse override %q: %w", path, unmarshalErr)
		}
		if ov.Control == "" {
			return fmt.Errorf("override %q missing 'control' field", path)
		}

		idx.overrides[kernel.ControlID(ov.Control)] = TriageProse{
			Defect:    ov.Defect,
			Infection: ov.Infection,
			Failure:   ov.Failure,
		}
	}
	return nil
}

func loadFamiliesFS(fsys fs.FS, dir string, idx *TriageIndex) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		// See loadOverridesFS: errors.Is(err, fs.ErrNotExist) is the
		// modern, consolidated spelling for "directory missing".
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return fmt.Errorf("read family %q: %w", path, readErr)
		}

		var fam yamlTriageFamily
		if unmarshalErr := yamlv3.Unmarshal(data, &fam); unmarshalErr != nil {
			return fmt.Errorf("parse family %q: %w", path, unmarshalErr)
		}
		if fam.Family == "" {
			return fmt.Errorf("family %q missing 'family' field", path)
		}

		idx.families = append(idx.families, familyEntry{
			prefix: fam.Family,
			prose: TriageProse{
				Infection: fam.Infection,
				Failure:   fam.Failure,
			},
		})
	}
	return nil
}

// ApplyTriage fills empty Defect/Infection/Failure fields on controls
// from the triage index. Per-control inline fields (already populated
// from the YAML) act as lowest-priority fallback — they are only
// overwritten when the triage index provides a non-empty value.
func ApplyTriage(controls []policy.ControlDefinition, idx *TriageIndex) {
	for i := range controls {
		resolved := idx.Resolve(controls[i].ID)
		if resolved.Defect != "" && controls[i].Defect == "" {
			controls[i].Defect = resolved.Defect
		}
		if resolved.Infection != "" && controls[i].Infection == "" {
			controls[i].Infection = resolved.Infection
		}
		if resolved.Failure != "" && controls[i].Failure == "" {
			controls[i].Failure = resolved.Failure
		}
	}
	DeriveDefects(controls)
}

// DeriveDefects fills empty Defect fields by generating descriptions
// from the control's predicate tree. Only applies to controls that
// still have empty Defect after triage override and family template
// inheritance. Uses the property-path registry to produce domain-
// meaningful labels; controls whose predicates contain unlabeled paths
// are skipped (accuracy over coverage).
func DeriveDefects(controls []policy.ControlDefinition) {
	for i := range controls {
		if controls[i].Defect != "" {
			continue
		}
		derived := policy.DeriveDefect(&controls[i].UnsafePredicate)
		if derived != "" {
			controls[i].Defect = derived
		}
	}
}
