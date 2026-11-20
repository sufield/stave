package yaml

import (
	"cmp"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	yamlv3 "gopkg.in/yaml.v3"
)

// LoadChains reads all YAML chain definitions from a directory.
// Returns validated, sorted chain definitions. The registry argument
// supplies the closed vocabulary of capability strings; chains
// referencing capabilities outside the registry are rejected. A nil
// registry skips capability validation (structural validation still
// runs).
func LoadChains(dir string, registry policy.CapabilityRegistry) ([]policy.ChainDefinition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no chains directory is valid
		}
		return nil, fmt.Errorf("read chains directory %q: %w", dir, err)
	}

	var chains []policy.ChainDefinition
	idSources := make(map[kernel.ChainID]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Accept both .yaml and .yml, matching isControlFile in
		// snapshot_loader.go. The previous .yaml-only check silently
		// dropped chain definitions named *.yml even though the
		// schema accepts either extension.
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, readErr := fsutil.ReadFileLimited(path)
		if readErr != nil {
			return nil, fmt.Errorf("read chain %q: %w", path, readErr)
		}

		chain, parseErr := parseAndValidateChain(data, path, registry, idSources)
		if parseErr != nil {
			return nil, parseErr
		}
		chains = append(chains, chain)
	}

	slices.SortFunc(chains, func(a, b policy.ChainDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return chains, nil
}

// LoadChainsFS reads chain definitions from an fs.FS rooted at dir.
func LoadChainsFS(fsys fs.FS, dir string, registry policy.CapabilityRegistry) ([]policy.ChainDefinition, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read embedded chains %q: %w", dir, err)
	}

	var chains []policy.ChainDefinition
	idSources := make(map[kernel.ChainID]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := dir + "/" + entry.Name()
		data, readErr := fs.ReadFile(fsys, path)
		if readErr != nil {
			return nil, fmt.Errorf("read chain %q: %w", path, readErr)
		}

		chain, parseErr := parseAndValidateChain(data, path, registry, idSources)
		if parseErr != nil {
			return nil, parseErr
		}
		chains = append(chains, chain)
	}

	slices.SortFunc(chains, func(a, b policy.ChainDefinition) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return chains, nil
}

func parseAndValidateChain(data []byte, path string, registry policy.CapabilityRegistry, idSources map[kernel.ChainID]string) (policy.ChainDefinition, error) {
	var chain policy.ChainDefinition
	if err := yamlv3.Unmarshal(data, &chain); err != nil {
		return chain, fmt.Errorf("parse chain %q: %w", path, err)
	}
	if err := chain.Validate(); err != nil {
		return chain, fmt.Errorf("validate chain %q: %w", path, err)
	}
	if err := chain.ValidateCapabilities(registry); err != nil {
		return chain, fmt.Errorf("validate chain %q: %w", path, err)
	}
	if existing, ok := idSources[chain.ID]; ok {
		return chain, fmt.Errorf("duplicate chain ID %q found in %q and %q", chain.ID, existing, path)
	}
	idSources[chain.ID] = path
	return chain, nil
}
