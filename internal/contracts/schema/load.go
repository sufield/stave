package schema

import (
	"embed"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
)

const (
	KindControl     = "control"
	KindObservation = "observation"
	KindFinding     = "finding"
	KindOutput      = "output"
	KindDiagnose    = "diagnose"
)

//go:embed embedded/*/*/*.json
var embeddedSchemas embed.FS

type schemaKind string

const (
	schemaKindControl     schemaKind = KindControl
	schemaKindObservation schemaKind = KindObservation
	schemaKindFinding     schemaKind = KindFinding
	schemaKindOutput      schemaKind = KindOutput
	schemaKindDiagnose    schemaKind = KindDiagnose
)

type schemaDescriptor struct {
	kind      schemaKind
	version   string
	path      string
	isDefault bool
}

// schemaRegistry is the single source of truth for embedded contract schemas.
var schemaRegistry = []schemaDescriptor{
	{
		kind:      schemaKindControl,
		version:   kernel.RegistryLayoutStandard,
		path:      "embedded/control/v1/control.schema.json",
		isDefault: true,
	},
	{
		kind:      schemaKindObservation,
		version:   kernel.RegistryLayoutStandard,
		path:      "embedded/observation/v1/observation.schema.json",
		isDefault: true,
	},
	{
		kind:      schemaKindFinding,
		version:   kernel.RegistryLayoutStandard,
		path:      "embedded/finding/v1/finding.schema.json",
		isDefault: true,
	},
	{
		kind:      schemaKindOutput,
		version:   kernel.RegistryLayoutLegacyOutput,
		path:      "embedded/output/v0.1/output.schema.json",
		isDefault: true,
	},
	{
		kind:      schemaKindDiagnose,
		version:   kernel.RegistryLayoutStandard,
		path:      "embedded/diagnose/v1/diagnose.schema.json",
		isDefault: true,
	},
}

func parseKind(raw string) (schemaKind, error) {
	kind := schemaKind(strings.TrimSpace(raw))
	switch kind {
	case schemaKindControl, schemaKindObservation, schemaKindFinding, schemaKindOutput, schemaKindDiagnose:
		return kind, nil
	default:
		return "", fmt.Errorf("unsupported schema kind %q", strings.TrimSpace(raw))
	}
}

func supportedVersions(kind schemaKind) []string {
	versions := make([]string, 0, len(schemaRegistry))
	for _, desc := range schemaRegistry {
		if desc.kind != kind {
			continue
		}
		versions = append(versions, desc.version)
	}
	slices.Sort(versions)
	return versions
}

func resolveDescriptor(kind schemaKind, version string) (schemaDescriptor, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		for _, desc := range schemaRegistry {
			if desc.kind == kind && desc.isDefault {
				return desc, nil
			}
		}
		return schemaDescriptor{}, fmt.Errorf("no default schema version configured for kind %q", kind)
	}
	for _, desc := range schemaRegistry {
		if desc.kind == kind && desc.version == version {
			return desc, nil
		}
	}
	return schemaDescriptor{}, fmt.Errorf(
		"unsupported schema version %q for kind %q (supported: %s)",
		version, kind, strings.Join(supportedVersions(kind), ", "),
	)
}

// ResolveVersion returns the effective schema version for a kind.
func ResolveVersion(kind string, version string) (string, error) {
	parsedKind, err := parseKind(kind)
	if err != nil {
		return "", err
	}
	desc, err := resolveDescriptor(parsedKind, version)
	if err != nil {
		return "", err
	}
	return desc.version, nil
}

// LoadSchema loads an embedded schema by kind and version.
func LoadSchema(kind string, version string) ([]byte, error) {
	parsedKind, err := parseKind(kind)
	if err != nil {
		return nil, err
	}
	desc, err := resolveDescriptor(parsedKind, version)
	if err != nil {
		return nil, err
	}
	schemaPath := desc.path
	if !path.IsAbs(schemaPath) && strings.Contains(schemaPath, "..") {
		return nil, fmt.Errorf("invalid embedded schema path %q", schemaPath)
	}
	b, err := embeddedSchemas.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("read embedded schema %q: %w", schemaPath, err)
	}
	return b, nil
}
