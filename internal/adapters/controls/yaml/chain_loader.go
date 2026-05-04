package yaml

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	policy "github.com/sufield/stave/internal/core/controldef"
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

		var chain policy.ChainDefinition
		if unmarshalErr := yamlv3.Unmarshal(data, &chain); unmarshalErr != nil {
			return nil, fmt.Errorf("parse chain %q: %w", path, unmarshalErr)
		}

		if validateErr := chain.Validate(); validateErr != nil {
			return nil, fmt.Errorf("validate chain %q: %w", path, validateErr)
		}

		if capErr := chain.ValidateCapabilities(registry); capErr != nil {
			return nil, fmt.Errorf("validate chain %q: %w", path, capErr)
		}

		chains = append(chains, chain)
	}

	sort.Slice(chains, func(i, j int) bool {
		return chains[i].ID < chains[j].ID
	})

	return chains, nil
}
