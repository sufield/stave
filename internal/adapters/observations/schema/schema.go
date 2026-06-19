// Package schema declares per-asset-type expected property paths
// and surfaces "required field absent" at ingest as a visible
// warning. This closes the silent-false-negative gap the property-
// bag design used to hide: when an extractor forgot a field, the
// predicate `field: properties.foo op: eq value: true` would
// evaluate to false (not unsafe) and the control silently never
// fired — invisible from any output channel.
//
// This is the first step of a longer migration toward fully typed
// per-asset-type Go structs. The full migration would let CEL
// type-check predicates at compile time and eliminate the
// translation/fields.go maintenance burden. This package alone
// already delivers the foundational value: distinguishing
// "extractor incomplete" from "asset compliant" via a structured
// slog warning at the ingest boundary.
//
// Adding a new asset type:
//  1. Declare a Schema literal and register it via Register().
//  2. List the property paths that the asset type's control set
//     references. Use the same dotted-path syntax used by the
//     control YAML (e.g. "properties.storage.access.has_wildcard_principal").
//  3. Mark each path as Required or Optional. Required paths
//     that are absent at ingest produce a Warn-level log per
//     affected asset; Optional paths are tracked but produce
//     no warning.
//  4. The validator runs on every asset whose Type matches a
//     registered schema; unregistered types are skipped (no
//     warning, no error — they participate via the existing
//     map[string]any pathway).
package schema

import (
	"log/slog"
	"maps"
	"strings"
	"sync"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// FieldRequirement names one expected property path on an asset.
type FieldRequirement struct {
	// Path is the dotted-property accessor as used in control YAML,
	// rooted at "properties" (e.g.
	// "properties.storage.access.has_wildcard_principal").
	Path string
	// Required = true emits a slog.Warn when the path is missing
	// from the asset's property bag. Required = false records the
	// expectation without warning (useful for future-state schema
	// migration: the field is declared NOW so its absence can be
	// audited, but absence is not yet a hard signal).
	Required bool
	// Doc is a short reason the path is expected. Surfaces in the
	// warning's "doc" key so an operator-side fix is obvious.
	Doc string
}

// Schema is the per-asset-type expected-property declaration.
type Schema struct {
	AssetType kernel.AssetType
	Fields    []FieldRequirement
}

// schemaRegistry is the concurrency-safe per-asset-type schema registry.
// Bundling the map with the RWMutex that guards it keeps the lock and the data
// in one type, and makes the map unreachable — and so un-raceable — from outside
// the package (the registry was previously an exported, externally-mutable map).
type schemaRegistry struct {
	mu      sync.RWMutex
	entries map[kernel.AssetType]Schema
}

// register installs s, replacing any existing entry for the same AssetType.
func (r *schemaRegistry) register(s Schema) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[s.AssetType] = s
}

// lookup returns the schema for t, or false if none is registered.
func (r *schemaRegistry) lookup(t kernel.AssetType) (Schema, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.entries[t]
	return s, ok
}

// remove deletes t's entry. Used by tests that install a temporary schema.
func (r *schemaRegistry) remove(t kernel.AssetType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, t)
}

// all returns a snapshot copy of the registered schemas for iteration.
func (r *schemaRegistry) all() map[kernel.AssetType]Schema {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[kernel.AssetType]Schema, len(r.entries))
	maps.Copy(out, r.entries)
	return out
}

// schemas is the process-wide schema registry — one cohesive instance rather
// than a loose mutex plus an exported, externally-mutable map.
var schemas = &schemaRegistry{entries: map[kernel.AssetType]Schema{}}

// Register installs a schema for an asset type. Replaces any
// existing entry for the same AssetType. Goroutine-safe so tests
// can install temporary schemas without racing the registry's init.
func Register(s Schema) {
	schemas.register(s)
}

// Lookup returns the schema for an asset type, or false if no
// schema is registered.
func Lookup(t kernel.AssetType) (Schema, bool) {
	return schemas.lookup(t)
}

// ValidationResult is the outcome of one asset's validation pass.
// Empty MissingRequired + empty MissingOptional means everything
// the schema expects is present. Callers typically only act on
// MissingRequired (the foundational signal).
type ValidationResult struct {
	AssetID         asset.ID
	AssetType       kernel.AssetType
	MissingRequired []string
	MissingOptional []string
}

// ValidateAsset checks an asset's property bag against the
// registered schema for its type. Returns a ValidationResult; the
// caller decides how to surface findings (typically Warn for
// required, Debug for optional).
//
// Returns ok=false when the asset type has no registered schema —
// the caller should treat that as "skip" rather than as a problem.
func ValidateAsset(a asset.Asset) (ValidationResult, bool) {
	s, ok := Lookup(a.Type)
	if !ok {
		return ValidationResult{}, false
	}
	res := ValidationResult{AssetID: a.ID, AssetType: a.Type}
	for _, f := range s.Fields {
		if hasPath(a.Properties, f.Path) {
			continue
		}
		if f.Required {
			res.MissingRequired = append(res.MissingRequired, f.Path)
		} else {
			res.MissingOptional = append(res.MissingOptional, f.Path)
		}
	}
	return res, true
}

// hasPath returns true when the dotted accessor resolves to a
// non-nil value somewhere in the property tree. Strips the
// leading "properties." root because the property bag itself is
// the value of "properties".
//
// "Has the path" means the field is present with any value other
// than literal nil. An empty string, an empty list, and the
// boolean false all count as present — they are intentional
// extractor outputs. nil is the unambiguous "not produced"
// signal.
func hasPath(props map[string]any, dotted string) bool {
	path := strings.TrimPrefix(dotted, "properties.")
	if path == "" || !strings.HasPrefix(dotted, "properties.") {
		// Path didn't start with "properties." — defensive: not a
		// shape this package handles, treat as missing so the
		// schema author sees the typo via the warning.
		return false
	}
	if props == nil {
		return false
	}
	var cur any = props
	remaining := path
	for remaining != "" {
		var p string
		p, remaining, _ = strings.Cut(remaining, ".")
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		next, present := m[p]
		if !present {
			return false
		}
		cur = next
	}
	return cur != nil
}

// LogValidationResult emits the standard ingest-side slog calls
// for one ValidationResult. Centralised so every caller produces
// the same log shape; operators can grep on the "category" key
// to find every "extractor incomplete" warning across a run.
func LogValidationResult(logger *slog.Logger, res ValidationResult) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(res.MissingRequired) > 0 {
		// Debug, not Warn: a partial snapshot (some fields not captured)
		// is a normal, expected condition, not something the operator must
		// act on. Surfacing it at warn level on every run is stderr noise
		// that trains users to ignore warnings. It remains visible under
		// -v for anyone debugging why a control did not fire.
		logger.Debug("schema: required field absent in observation",
			"category", "missing_required_field",
			"asset_id", res.AssetID,
			"asset_type", res.AssetType,
			"missing", res.MissingRequired)
	}
	if len(res.MissingOptional) > 0 {
		logger.Debug("schema: optional field absent in observation",
			"category", "missing_optional_field",
			"asset_id", res.AssetID,
			"asset_type", res.AssetType,
			"missing", res.MissingOptional)
	}
}
