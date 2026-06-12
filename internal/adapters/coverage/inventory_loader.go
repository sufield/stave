// Package coverage adapts external inventory data files
// (data/alternatives/*.yaml) into the controldef-side
// coverage.ToolInventory representation consumed by the core
// aggregation. Belongs in adapters because it touches the filesystem
// and the YAML wire format; core stays opaque to both.
package coverage

import (
	"cmp"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	corecov "github.com/sufield/stave/internal/core/evaluation/coverage"
	"gopkg.in/yaml.v3"
)

//go:embed embedded/*.yaml
var embeddedFS embed.FS

const embeddedRoot = "embedded"

// yamlInventory mirrors the on-disk file shape: one (tool, domain) per
// file plus a flat list of check IDs.
type yamlInventory struct {
	Tool    string             `yaml:"tool"`
	Domain  string             `yaml:"domain"`
	Checks  []yamlInventoryRow `yaml:"checks"`
	Comment string             `yaml:"-"`
}

type yamlInventoryRow struct {
	ID string `yaml:"id"`
}

// LoadEmbedded reads every *.yaml file under the embedded inventory
// directory. The result is suitable for direct use with
// coverage.BuildCoverageIndex.
//
// Returns an error when two files declare the same (tool, domain) pair
// or when a file is malformed; partial loads are not tolerated because
// silent inventory loss would skew coverage counts.
func LoadEmbedded() ([]corecov.ToolInventory, error) {
	return loadFromFS(embeddedFS, embeddedRoot)
}

// loadFromFS is the testable core: walks the given fs.FS rooted at
// `root` and parses every .yaml file into a ToolInventory.
func loadFromFS(fsys fs.FS, root string) ([]corecov.ToolInventory, error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, fmt.Errorf("read inventory dir %q: %w", root, err)
	}

	var (
		out  []corecov.ToolInventory
		seen = make(map[string]string) // tool|domain -> source file
	)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		fullPath := path.Join(root, name)
		inv, err := parseInventoryFile(fsys, fullPath)
		if err != nil {
			return nil, err
		}
		key := inv.Tool + "|" + inv.Domain
		if existing, dup := seen[key]; dup {
			return nil, fmt.Errorf("duplicate inventory for tool=%q domain=%q in %q (also in %q)", inv.Tool, inv.Domain, fullPath, existing)
		}
		seen[key] = fullPath
		out = append(out, inv)
	}

	slices.SortFunc(out, func(a, b corecov.ToolInventory) int {
		if a.Tool != b.Tool {
			return cmp.Compare(a.Tool, b.Tool)
		}
		return cmp.Compare(a.Domain, b.Domain)
	})
	return out, nil
}

func parseInventoryFile(fsys fs.FS, fullPath string) (corecov.ToolInventory, error) {
	data, err := fs.ReadFile(fsys, fullPath)
	if err != nil {
		return corecov.ToolInventory{}, fmt.Errorf("read %q: %w", fullPath, err)
	}
	var dto yamlInventory
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return corecov.ToolInventory{}, fmt.Errorf("parse %q: %w", fullPath, err)
	}
	if dto.Tool == "" {
		return corecov.ToolInventory{}, fmt.Errorf("%q: tool field is required", fullPath)
	}
	if dto.Domain == "" {
		return corecov.ToolInventory{}, fmt.Errorf("%q: domain field is required", fullPath)
	}
	checks := make([]string, 0, len(dto.Checks))
	for i, row := range dto.Checks {
		if row.ID == "" {
			return corecov.ToolInventory{}, fmt.Errorf("%q: checks[%d].id is empty", fullPath, i)
		}
		checks = append(checks, row.ID)
	}
	return corecov.ToolInventory{
		Tool:   dto.Tool,
		Domain: dto.Domain,
		Checks: checks,
	}, nil
}
