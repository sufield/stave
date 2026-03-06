package validator

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	"gopkg.in/yaml.v3"
)

// NOTE FOR MAINTAINERS:
// Keep this file focused on core Validator orchestration.
// If schema diagnostics, YAML conversion, or format detection logic grows,
// move those concerns into dedicated files in this package to avoid a
// catch-all "dumping ground" file.

type Diagnostic struct {
	Path    string               `json:"path"`
	Message string               `json:"message"`
	Kind    jsonschema.ErrorKind `json:"-"` // typed error from the schema library; nil for synthetic diagnostics
}

type Validator struct {
	compiler *jsonschema.Compiler
	compiled map[string]*jsonschema.Schema
}

func key(kind, version string) string {
	return strings.TrimSpace(kind) + ":" + strings.TrimSpace(version)
}

func New() *Validator {
	return &Validator{
		compiler: jsonschema.NewCompiler(),
		compiled: make(map[string]*jsonschema.Schema),
	}
}

func (v *Validator) schema(kind, version string) (*jsonschema.Schema, error) {
	var err error
	version, err = schemas.ResolveVersion(kind, version)
	if err != nil {
		return nil, err
	}
	cacheKey := key(kind, version)
	if s, ok := v.compiled[cacheKey]; ok {
		return s, nil
	}

	raw, err := schemas.LoadSchema(kind, version)
	if err != nil {
		return nil, err
	}
	var doc any
	if err = json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse schema %s/%s: %w", kind, version, err)
	}

	schemaID := fmt.Sprintf("urn:stave:schema:%s:%s", kind, version)
	if err = v.compiler.AddResource(schemaID, doc); err != nil {
		return nil, fmt.Errorf("add schema %s/%s: %w", kind, version, err)
	}
	s, err := v.compiler.Compile(schemaID)
	if err != nil {
		return nil, fmt.Errorf("compile schema %s/%s: %w", kind, version, err)
	}
	v.compiled[cacheKey] = s
	return s, nil
}

func yamlToJSONBytes(raw []byte) ([]byte, error) {
	var y any
	if err := yaml.Unmarshal(raw, &y); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	j, err := json.Marshal(convertYAML(y))
	if err != nil {
		return nil, fmt.Errorf("yaml->json conversion failed: %w", err)
	}
	return j, nil
}

func convertYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = convertYAML(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = convertYAML(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = convertYAML(x[i])
		}
		return out
	default:
		return v
	}
}

func flatten(err *jsonschema.ValidationError, out *[]*jsonschema.ValidationError) {
	if err.ErrorKind != nil {
		*out = append(*out, err)
	}
	for _, c := range err.Causes {
		flatten(c, out)
	}
}

func normalizePath(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	return "/" + strings.Join(parts, "/")
}

func normalizeMessage(msg string) string {
	if strings.TrimSpace(msg) == "" {
		return "schema violation"
	}
	return strings.TrimSpace(msg)
}

func sortDiagnostics(ds []Diagnostic) {
	slices.SortFunc(ds, func(a, b Diagnostic) int {
		if n := cmp.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return cmp.Compare(a.Message, b.Message)
	})
}

func diagnosticsFromError(err error) []Diagnostic {
	verr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return []Diagnostic{{
			Path:    "/",
			Message: normalizeMessage(err.Error()),
		}}
	}
	var flat []*jsonschema.ValidationError
	flatten(verr, &flat)
	out := make([]Diagnostic, 0, len(flat))
	for _, item := range flat {
		out = append(out, Diagnostic{
			Path:    normalizePath(item.InstanceLocation),
			Message: normalizeMessage(item.Error()),
			Kind:    item.ErrorKind,
		})
	}
	sortDiagnostics(out)
	return out
}

func IsLikelyYAML(raw []byte) bool {
	trim := strings.TrimSpace(string(raw))
	if trim == "" {
		return false
	}
	return !strings.HasPrefix(trim, "{") && !strings.HasPrefix(trim, "[")
}

func (v *Validator) Validate(kind, version string, raw []byte, isYAML bool) ([]Diagnostic, error) {
	s, err := v.schema(kind, version)
	if err != nil {
		return nil, err
	}

	var jsonBytes []byte
	if isYAML {
		jsonBytes, err = yamlToJSONBytes(raw)
		if err != nil {
			return []Diagnostic{{Path: "/", Message: err.Error()}}, nil
		}
	} else {
		jsonBytes = raw
	}

	var payload any
	if err = json.Unmarshal(jsonBytes, &payload); err != nil {
		return []Diagnostic{{Path: "/", Message: "invalid JSON: " + err.Error()}}, nil
	}
	if err = s.Validate(payload); err != nil {
		return diagnosticsFromError(err), nil
	}
	return nil, nil
}
