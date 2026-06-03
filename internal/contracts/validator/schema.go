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
	"github.com/sufield/stave/internal/core/diag"
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

// Diagnostics is a named slice of Diagnostic. Carries the
// Diagnostics-to-Error bridge (ToError) as a first-class method so
// the conversion has a documented home rather than being
// re-implemented at every call site.
type Diagnostics []Diagnostic

// ToError converts a diagnostic collection into a standard Go
// error so callers using the conventional `if err != nil` pattern
// detect failures without having to inspect Diagnostics.Failed()
// or the slice itself. The full diagnostic list stays available
// via the original return value; this is purely the bridge to
// idiomatic error handling.
//
// Returns nil for an empty collection — "no diagnostics" is not
// an error. The first diagnostic's message becomes the error
// summary; the remaining diagnostics are accessible from the
// caller-side slice if a richer rendering is needed.
func (d Diagnostics) ToError() error {
	if len(d) == 0 {
		return nil
	}
	return fmt.Errorf("schema parse failed: %s", d[0].Message)
}

// Request captures context for a single schema validation call.
type Request struct {
	Kind          schemas.Kind
	ActualVersion string
	Data          []byte
	IsYAML        bool
}

// ParsedPayload deserialises Data using the format the request
// declares (YAML when IsYAML, JSON otherwise) and returns the result
// the schema engine can validate. Centralises the parser switch so
// Validator.Validate stops branching on IsYAML; future formats land
// as a single case here instead of a multi-site update.
//
// A parse error is returned as a single-element diagnostic slice in
// the second return so callers can surface the parser failure as a
// validation finding without needing a separate error path. Both
// returns are non-nil simultaneously only on parse failure; on
// success diags is nil.
func (r Request) ParsedPayload() (payload any, parseDiags []Diagnostic) {
	if r.IsYAML {
		var rawYAML any
		if err := yaml.Unmarshal(r.Data, &rawYAML); err != nil {
			return nil, []Diagnostic{{Path: "/", Message: "invalid YAML: " + err.Error()}}
		}
		return normalizeYAML(rawYAML), nil
	}
	var p any
	if err := json.Unmarshal(r.Data, &p); err != nil {
		return nil, []Diagnostic{{Path: "/", Message: "invalid JSON: " + err.Error()}}
	}
	return p, nil
}

// RequestValidator runs schema validation against a typed Request.
// The Request.Kind discriminator selects which schema is applied. Used by
// callers that already have a Request value (e.g. JSON output writers).
type RequestValidator interface {
	Validate(req Request) ([]Diagnostic, error)
}

// ControlYAMLValidator validates control YAML documents.
// Implemented by *Validator.
type ControlYAMLValidator interface {
	ValidateControlYAML(raw []byte, opts ...Option) (*diag.Assessment, error)
}

// ObservationJSONValidator validates observation JSON documents.
// Implemented by *Validator.
type ObservationJSONValidator interface {
	ValidateObservationJSON(raw []byte, opts ...Option) (*diag.Assessment, error)
}

// SchemaValidator is the umbrella interface composing all three
// document-kind validators. Adapter and app-layer code that needs to
// validate multiple document kinds depends on this; consumers that
// only need one kind should depend on the narrower interface (ISP).
type SchemaValidator interface {
	RequestValidator
	ControlYAMLValidator
	ObservationJSONValidator
}

// Validator manages the compilation and caching of JSON schemas.
//
// Concurrency: safe for use by multiple goroutines via the lock
// contract below. The internal jsonschema.Compiler is NOT
// goroutine-safe — its resolver mutates internal state during
// schema compilation — so every read or write of `compiler` and
// `compiled` must happen under `mu`. Cache hits use mu.RLock();
// compilation (which mutates the compiler AND inserts into the
// compiled map) uses mu.Lock(). Adding a field that the schema
// engine touches outside this contract requires extending the lock
// scope in lockstep.
type Validator struct {
	// compiler MUST be accessed only while holding mu.Lock(). The
	// jsonschema package's compile path mutates the compiler's
	// internal resolver state, so even read-style accesses need
	// the exclusive lock — RLock is insufficient. mu.RLock() is
	// reserved for `compiled` cache lookups that don't reach into
	// the compiler.
	compiler *jsonschema.Compiler

	mu sync.RWMutex
	// compiled maps "<kind>:<version>" → cached *jsonschema.Schema.
	// Reads under mu.RLock(); writes (only on first compilation
	// for a given key) under mu.Lock() alongside compiler use.
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

	payload, parseDiags := req.ParsedPayload()
	if parseDiags != nil {
		// Parse failures are the only path that returns BOTH
		// non-nil diagnostics AND a non-nil error from Validate.
		// Surfacing through both channels lets callers using the
		// conventional `if err != nil` pattern catch the failure
		// while the diagnostics-aware path (validateDocument) folds
		// the same failure into a *diag.Assessment.
		//
		// The receiver-side contract — see validateDocument in
		// issues.go — deliberately subsumes the error when
		// diagnostics are present so its callers see exactly one
		// authoritative signal (the assessment). Editors of either
		// side must keep these two contracts in lockstep: a
		// diagnostic list returned alongside a non-nil error must
		// always describe the same failure.
		return parseDiags, Diagnostics(parseDiags).ToError()
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
		return nil, fmt.Errorf("resolve schema version: %w", err)
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
		return nil, fmt.Errorf("load schema %s/%s: %w", kind, ver, err)
	}

	var doc any
	if unmarshalErr := json.Unmarshal(raw, &doc); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse schema %s/%s: %w", kind, ver, unmarshalErr)
	}

	// Register any auxiliary sub-schemas (e.g. per-asset-type
	// JSON Schemas under observation/v1/asset-types/) with the
	// compiler BEFORE compiling the base. The base schema's
	// cross-file $ref strings — which name the sub-schemas by
	// their declared $id URN — only resolve once the resources
	// are registered. Sub-schemas are added under the same write
	// lock that compiles the base, so the compiler's
	// goroutine-unsafe state is touched in a single atomic
	// section per (kind, version) compilation.
	subSchemas, subErr := schemas.LoadSubSchemas(kind, ver)
	if subErr != nil {
		return nil, fmt.Errorf("load sub-schemas for %s/%s: %w", kind, ver, subErr)
	}
	for _, sub := range subSchemas {
		var subDoc any
		if unmarshalErr := json.Unmarshal(sub.Bytes, &subDoc); unmarshalErr != nil {
			return nil, fmt.Errorf("parse sub-schema %s: %w", sub.URI, unmarshalErr)
		}
		if addErr := v.compiler.AddResource(sub.URI, subDoc); addErr != nil {
			return nil, fmt.Errorf("add sub-schema resource %s: %w", sub.URI, addErr)
		}
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

// normalizeYAML recursively converts map[any]any to map[string]any
// for JSON schema compatibility. Both map branches and the slice
// branch return new collections rather than mutating their inputs;
// the previous shape mutated map[string]any in place, which had two
// failure modes:
//   - Callers holding a reference to the input map saw their values
//     change underneath them.
//   - The map[any]any branch already returned a fresh map, so the
//     two cases were asymmetric — a caller could not predict
//     whether normalizeYAML would or would not mutate the input.
//
// Normalising both branches to "always return a copy" makes the
// function pure with respect to its input.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeYAML(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalizeYAML(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeYAML(x[i])
		}
		return out
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

	// Defensive: a ValidationError with no ErrorKind anywhere in its
	// cause tree would otherwise yield an empty diagnostic slice and
	// silently drop the validation failure. Synthesize a diagnostic
	// from the root error so a non-nil vErr is *always* visible.
	if len(out) == 0 {
		out = append(out, Diagnostic{
			Path:    "/" + strings.Join(vErr.InstanceLocation, "/"),
			Message: vErr.Error(),
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
//
// Empty input returns true: the previous shape returned false, which
// implied "definitely JSON" and steered downstream parsers into a
// JSON unmarshal that produced confusing "unexpected end of JSON
// input" errors. YAML legitimately represents an empty document, so
// the heuristic stays consistent with the YAML spec rather than
// guessing JSON for content with no leading token.
func IsLikelyYAML(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return true
	}
	return s[0] != '{' && s[0] != '['
}
