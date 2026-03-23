// Package validator provides JSON schema validation for observation and control contracts.
package validator

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	"gopkg.in/yaml.v3"
)

// ErrSchemaValidationFailed indicates the input data did not meet the contract requirements.
var ErrSchemaValidationFailed = errors.New("schema validation failed")

// Diagnostic represents a specific point of failure within a document.
type Diagnostic struct {
	Path    string               `json:"path"`
	Message string               `json:"message"`
	Kind    jsonschema.ErrorKind `json:"-"` // Opaque type from the engine
}

// Request captures context for a single schema validation call.
type Request struct {
	Kind          schemas.Kind
	ActualVersion string
	Data          []byte
	IsYAML        bool
}

// Validator manages the compilation and caching of JSON schemas.
// It is safe for concurrent use by multiple goroutines.
type Validator struct {
	compiler *jsonschema.Compiler

	mu       sync.RWMutex
	compiled map[string]*jsonschema.Schema
}

// New creates an initialized Validator with an empty schema cache.
func New() *Validator {
	return &Validator{
		compiler: jsonschema.NewCompiler(),
		compiled: make(map[string]*jsonschema.Schema),
	}
}

// Validate executes the appropriate schema check based on the provided request.
func (v *Validator) Validate(req Request) ([]Diagnostic, error) {
	s, err := v.getSchema(req.Kind, req.ActualVersion)
	if err != nil {
		return nil, err
	}

	// Prepare JSON payload (converting from YAML if necessary)
	var payload any
	if req.IsYAML {
		var rawYAML any
		if err := yaml.Unmarshal(req.Data, &rawYAML); err != nil {
			return []Diagnostic{{Path: "/", Message: "invalid YAML: " + err.Error()}}, nil
		}
		payload = normalizeYAML(rawYAML)
	} else {
		if err := json.Unmarshal(req.Data, &payload); err != nil {
			return []Diagnostic{{Path: "/", Message: "invalid JSON: " + err.Error()}}, nil
		}
	}

	// Execute validation
	if err := s.Validate(payload); err != nil {
		return flattenErrors(err), nil
	}

	return nil, nil
}

// --- Internal Schema Management ---

func (v *Validator) getSchema(kind schemas.Kind, version string) (*jsonschema.Schema, error) {
	ver, err := schemas.ResolveVersion(kind, version)
	if err != nil {
		return nil, err
	}

	cacheKey := fmt.Sprintf("%s:%s", kind, ver)

	// Read-lock for cache hits
	v.mu.RLock()
	s, ok := v.compiled[cacheKey]
	v.mu.RUnlock()
	if ok {
		return s, nil
	}

	// Write-lock for compilation
	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := v.compiled[cacheKey]; ok {
		return cached, nil
	}

	raw, err := schemas.LoadSchema(kind, ver)
	if err != nil {
		return nil, err
	}

	var doc any
	if unmarshalErr := json.Unmarshal(raw, &doc); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse schema %s/%s: %w", kind, ver, unmarshalErr)
	}

	schemaID := fmt.Sprintf("urn:stave:schema:%s:%s", kind, ver)
	if addErr := v.compiler.AddResource(schemaID, doc); addErr != nil {
		return nil, fmt.Errorf("failed to add schema resource: %w", addErr)
	}

	s, err = v.compiler.Compile(schemaID)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", err)
	}

	v.compiled[cacheKey] = s
	return s, nil
}

// --- Utilities ---

// normalizeYAML recursively converts map[any]any to map[string]any for JSON schema compatibility.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = normalizeYAML(vv)
		}
		return x
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalizeYAML(vv)
		}
		return out
	case []any:
		for i := range x {
			x[i] = normalizeYAML(x[i])
		}
		return x
	default:
		return v
	}
}

// flattenErrors converts a tree of validation errors into a flat list of diagnostics.
func flattenErrors(err error) []Diagnostic {
	var vErr *jsonschema.ValidationError
	if !errors.As(err, &vErr) {
		return []Diagnostic{{Path: "/", Message: err.Error()}}
	}

	var flat []*jsonschema.ValidationError
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if e.ErrorKind != nil {
			flat = append(flat, e)
		}
		for _, cause := range e.Causes {
			walk(cause)
		}
	}
	walk(vErr)

	out := make([]Diagnostic, 0, len(flat))
	for _, item := range flat {
		out = append(out, Diagnostic{
			Path:    "/" + strings.Join(item.InstanceLocation, "/"),
			Message: item.Error(),
			Kind:    item.ErrorKind,
		})
	}

	slices.SortFunc(out, func(a, b Diagnostic) int {
		return cmp.Or(
			cmp.Compare(a.Path, b.Path),
			cmp.Compare(a.Message, b.Message),
		)
	})

	return out
}

// IsLikelyYAML performs a heuristic check to see if bytes represent YAML or JSON.
func IsLikelyYAML(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return false
	}
	return s[0] != '{' && s[0] != '['
}
