package pack

import (
	"embed"
	"fmt"
	"maps"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var dataFS embed.FS

// Load returns the embedded pack by name.
func Load(name string) (*Pack, error) {
	all, err := LoadAll()
	if err != nil {
		return nil, err
	}
	p, ok := all[name]
	if !ok {
		return nil, fmt.Errorf("unknown pack %q (available: %s)", name, strings.Join(Names(all), ", "))
	}
	return p, nil
}

// LoadAll parses every embedded pack, keyed by name.
func LoadAll() (map[string]*Pack, error) {
	entries, err := dataFS.ReadDir("data")
	if err != nil {
		return nil, fmt.Errorf("read embedded packs: %w", err)
	}
	out := map[string]*Pack{}
	for _, e := range entries {
		b, rerr := dataFS.ReadFile("data/" + e.Name())
		if rerr != nil {
			return nil, fmt.Errorf("read pack %q: %w", e.Name(), rerr)
		}
		var p Pack
		if uerr := yaml.Unmarshal(b, &p); uerr != nil {
			return nil, fmt.Errorf("parse pack %q: %w", e.Name(), uerr)
		}
		if p.Name == "" {
			return nil, fmt.Errorf("pack %q has no name", e.Name())
		}
		out[p.Name] = &p
	}
	return out, nil
}

// Names returns the sorted pack names of a loaded set.
func Names(all map[string]*Pack) []string {
	return slices.Sorted(maps.Keys(all))
}
