package schema

import (
	"embed"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Kind identifies the functional category of a schema.
type Kind string

const (
	KindControl     Kind = "control"
	KindObservation Kind = "observation"
	KindFinding     Kind = "finding"
	KindOutput      Kind = "output"
	KindDiagnose    Kind = "diagnose"
)

//go:embed embedded/*/*/*.json
var embeddedFS embed.FS

// registry maps (Kind -> Version) to the internal filesystem path.
var registry = map[Kind]map[string]string{
	KindControl: {
		kernel.RegistryLayoutStandard: "embedded/control/v1/control.schema.json",
	},
	KindObservation: {
		kernel.RegistryLayoutStandard: "embedded/observation/v1/observation.schema.json",
	},
	KindFinding: {
		kernel.RegistryLayoutStandard: "embedded/finding/v1/finding.schema.json",
	},
	KindOutput: {
		kernel.RegistryLayoutLegacyOutput: "embedded/output/v0.1/output.schema.json",
	},
	KindDiagnose: {
		kernel.RegistryLayoutStandard: "embedded/diagnose/v1/diagnose.schema.json",
	},
}

// defaultVersions maps a Kind to its preferred/default version key.
var defaultVersions = map[Kind]string{
	KindControl:     kernel.RegistryLayoutStandard,
	KindObservation: kernel.RegistryLayoutStandard,
	KindFinding:     kernel.RegistryLayoutStandard,
	KindOutput:      kernel.RegistryLayoutLegacyOutput,
	KindDiagnose:    kernel.RegistryLayoutStandard,
}

// ResolveVersion determines the effective version for a kind,
// falling back to the default if the version is empty.
func ResolveVersion(kind string, version string) (string, error) {
	k := Kind(strings.TrimSpace(kind))
	v := strings.TrimSpace(version)

	if v == "" {
		def, ok := defaultVersions[k]
		if !ok {
			return "", fmt.Errorf("no default version defined for schema kind %q", kind)
		}
		return def, nil
	}

	if _, ok := registry[k][v]; !ok {
		return "", fmt.Errorf("unsupported version %q for kind %q (available: %s)",
			v, kind, strings.Join(SupportedVersions(kind), ", "))
	}

	return v, nil
}

// LoadSchema retrieves the raw JSON bytes for a specific schema definition.
func LoadSchema(kind string, version string) ([]byte, error) {
	k := Kind(strings.TrimSpace(kind))

	v, err := ResolveVersion(kind, version)
	if err != nil {
		return nil, err
	}

	path, ok := registry[k][v]
	if !ok {
		return nil, fmt.Errorf("schema path mapping missing for %s:%s", k, v)
	}

	data, err := embeddedFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded schema at %q: %w", path, err)
	}

	return data, nil
}

// SupportedVersions returns all registered versions for a specific kind.
func SupportedVersions(kind string) []string {
	k := Kind(strings.TrimSpace(kind))
	versions, ok := registry[k]
	if !ok {
		return nil
	}

	out := make([]string, 0, len(versions))
	for v := range versions {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
