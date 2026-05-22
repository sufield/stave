package schema

import (
	"embed"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// ErrSchemaNotFound signals that no embedded schema is registered for
// the requested (kind, version). Callers can treat this as
// "validation unavailable for this kind" without parsing nil bytes
// as malformed JSON.
var ErrSchemaNotFound = errors.New("schema not found")

// Kind identifies the functional category of a schema.
type Kind string

// Schema kind constants identify the functional category of a schema.
const (
	KindControl     Kind = "control"
	KindObservation Kind = "observation"
	KindFinding     Kind = "finding"
	KindOutput      Kind = "output"
	KindDiagnose    Kind = "diagnose"
)

// Two patterns: the original three-level glob covers
// embedded/<kind>/<version>/<file>.json (control, observation,
// finding, output, diagnose root schemas). The four-level glob
// covers embedded/<kind>/<version>/<subdir>/<file>.json — used
// today only by observation/v1/asset-types/*.json (per-asset
// JSON Schema sub-schemas resolved via cross-file $ref in the
// base observation schema). Splitting the patterns explicitly,
// rather than collapsing to embedded/**/*.json (which Go embed
// does not support), keeps the embedded surface auditable: a
// new subdirectory under any kind/version is opt-in, not
// accidental.
//
//go:embed embedded/*/*/*.json
//go:embed embedded/*/*/*/*.json
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
		kernel.RegistryLayoutStandard: "embedded/output/v1/output.schema.json",
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
	KindOutput:      kernel.RegistryLayoutStandard,
	KindDiagnose:    kernel.RegistryLayoutStandard,
}

// ResolveVersion determines the effective version for a kind,
// falling back to the default if the version is empty.
func ResolveVersion(kind Kind, version string) (string, error) {
	k := Kind(strings.TrimSpace(string(kind)))
	v := strings.TrimSpace(version)

	if v == "" {
		def, ok := defaultVersions[k]
		if !ok {
			return "", fmt.Errorf("no default version defined for schema kind %q", k)
		}
		return def, nil
	}

	if _, ok := registry[k][v]; !ok {
		return "", fmt.Errorf("unsupported version %q for kind %q (available: %s)",
			v, k, strings.Join(SupportedVersions(k), ", "))
	}

	return v, nil
}

// LoadSchema retrieves the raw JSON bytes for a specific schema definition.
func LoadSchema(kind Kind, version string) ([]byte, error) {
	k := Kind(strings.TrimSpace(string(kind)))

	// Pass the trimmed kind to ResolveVersion so version-resolution
	// uses the same canonical key as the registry lookup below. The
	// previous shape passed the un-trimmed `kind`, which meant a
	// caller supplying " ctrl.v1" with stray whitespace would
	// resolve under one key and lookup under another — masking the
	// mismatch as a confusing "no such schema" instead of the
	// trimming gap the user actually hit.
	v, err := ResolveVersion(k, version)
	if err != nil {
		return nil, err
	}

	path, ok := registry[k][v]
	if !ok {
		// Returning (nil, nil) here let callers parse nil bytes as
		// JSON downstream and produce "unexpected end of JSON input"
		// — a misleading error that hid the real "no schema for this
		// kind" case. Surface a typed sentinel so the caller can
		// branch on errors.Is(err, ErrSchemaNotFound).
		return nil, fmt.Errorf("%w: kind=%q version=%q", ErrSchemaNotFound, kind, v)
	}

	data, err := embeddedFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded schema at %q: %w", path, err)
	}

	return data, nil
}

// SubSchema is one auxiliary schema embedded under
// <kind>/<version>/<subdir>/<file>.json. The Bytes are the
// raw JSON; the URI is the schema's stable identifier used to
// register the resource with the jsonschema compiler. Sub-schemas
// are loaded by their kind+version owner (the base schema's
// validator) and registered with the compiler before the base
// schema is compiled so cross-file $ref strings resolve.
type SubSchema struct {
	URI   string
	Bytes []byte
}

// LoadSubSchemas returns the auxiliary sub-schemas registered
// under the given kind+version. Today this covers
// observation/v1/asset-types/*.json — per-asset-type property
// schemas the base observation schema dispatches into via
// if/then. Other kinds return an empty slice.
//
// URI is derived from the file's $id when present, falling back
// to a urn:stave:schema:<kind>:<version>:<basename> URN. The
// compiler indexes the doc under both whichever the caller used
// in AddResource AND the doc's own $id, so cross-file $refs in
// the base schema referring to the sub-schema's $id resolve.
func LoadSubSchemas(kind Kind, version string) ([]SubSchema, error) {
	k := Kind(strings.TrimSpace(string(kind)))
	v, err := ResolveVersion(k, version)
	if err != nil {
		return nil, err
	}

	dir := fmt.Sprintf("embedded/%s/%s/asset-types", k, v)
	entries, err := embeddedFS.ReadDir(dir)
	if err != nil {
		// Missing sub-schema directory is non-fatal: the kind
		// simply has no auxiliary schemas registered. Callers
		// (the validator) treat a nil slice as "no sub-schemas
		// to register" rather than as a load failure.
		return nil, nil //nolint:nilerr // intentional: missing dir = no sub-schemas
	}

	out := make([]SubSchema, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := dir + "/" + e.Name()
		data, readErr := embeddedFS.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read sub-schema %q: %w", path, readErr)
		}
		uri := extractSchemaID(data)
		if uri == "" {
			// Fall back to a deterministic URN derived from the
			// file basename. This keeps the resource lookup table
			// populated even when an author forgets to set $id.
			base := strings.TrimSuffix(e.Name(), ".json")
			uri = fmt.Sprintf("urn:stave:schema:%s:%s:%s", k, v, base)
		}
		out = append(out, SubSchema{URI: uri, Bytes: data})
	}
	slices.SortFunc(out, func(a, b SubSchema) int { return strings.Compare(a.URI, b.URI) })
	return out, nil
}

// extractSchemaID does a small, dependency-free scan for the
// document's top-level "$id" string so the loader can prefer the
// schema's declared identifier as the AddResource URI. A full
// json.Unmarshal would also work, but parsing every sub-schema
// twice (here and in the compiler) is wasteful when we only need
// one field. The loader treats a missing $id as a soft fallback,
// not an error.
func extractSchemaID(data []byte) string {
	const key = `"$id"`
	idx := strings.Index(string(data), key)
	if idx < 0 {
		return ""
	}
	rest := string(data[idx+len(key):])
	// Expect: optional whitespace, ':', whitespace, '"value"'.
	rest = strings.TrimLeft(rest, " \t\n\r")
	if !strings.HasPrefix(rest, ":") {
		return ""
	}
	rest = strings.TrimLeft(rest[1:], " \t\n\r")
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	before, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return ""
	}
	return before
}

// SupportedVersions returns all registered versions for a specific kind.
func SupportedVersions(kind Kind) []string {
	k := Kind(strings.TrimSpace(string(kind)))
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

// AssetTypeSchema returns the embedded per-asset-type JSON Schema
// bytes for the given asset type (e.g. "aws_s3_bucket"). Returns
// ErrSchemaNotFound when no schema is registered for the type.
// Read-only; suitable for `stave contract show` and any tooling
// that wants to inspect per-type expectations without going through
// the JSON Schema compiler.
func AssetTypeSchema(assetType string) ([]byte, error) {
	at := strings.TrimSpace(assetType)
	if at == "" {
		return nil, fmt.Errorf("asset type is empty: %w", ErrSchemaNotFound)
	}
	v, err := ResolveVersion(KindObservation, "")
	if err != nil {
		return nil, err
	}
	path := fmt.Sprintf("embedded/%s/%s/asset-types/%s.schema.json", KindObservation, v, at)
	data, readErr := embeddedFS.ReadFile(path)
	if readErr != nil {
		return nil, fmt.Errorf("%s: %w", at, ErrSchemaNotFound)
	}
	return data, nil
}

// AssetTypesWithSchema returns the sorted list of asset types that
// have an embedded per-asset-type JSON Schema. Each entry is a bare
// asset-type identifier (e.g. "aws_s3_bucket"), matching the filename
// stem under embedded/observation/v1/asset-types/.
func AssetTypesWithSchema() []string {
	v, err := ResolveVersion(KindObservation, "")
	if err != nil {
		return nil
	}
	dir := fmt.Sprintf("embedded/%s/%s/asset-types", KindObservation, v)
	entries, err := embeddedFS.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".schema.json"))
	}
	slices.Sort(out)
	return out
}
