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
// Returns validated, sorted chain definitions.
func LoadChains(dir string) ([]policy.ChainDefinition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no chains directory is valid
		}
		return nil, fmt.Errorf("read chains directory %q: %w", dir, err)
	}

	var chains []policy.ChainDefinition
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
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

		chains = append(chains, chain)
	}

	sort.Slice(chains, func(i, j int) bool {
		return chains[i].ID < chains[j].ID
	})

	return chains, nil
}
