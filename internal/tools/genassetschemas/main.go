// Command genassetschemas generates per-asset-type JSON Schemas
// from the embedded control catalog. For each asset type with at
// least one control that declares it via applicable_asset_types,
// the tool walks every applicable control's unsafe_predicate AST,
// collects the (property_path, type) pairs referenced, and emits
// a JSON Schema (Draft 2020-12) under
// schemas/observation/v1/asset-types/<asset_type>.schema.json.
//
// The schemas are static artifacts. This first cut does NOT wire
// them into the base observation schema, the embedded validator,
// or the consistency-check gate — those steps belong to a
// follow-on commit, with their own test pass against existing
// observation fixtures. The generator outputs a discoverable
// per-asset-type contract that customers can validate against
// using any JSON Schema validator (Ajv, check-jsonschema, jv,
// etc.) before the runtime path picks them up.
//
// Property type inference is deterministic, sourced from the
// predicate's value: field via Operand.Raw():
//
//	value: true        →  "type": "boolean"
//	value: "phi"       →  "type": "string"
//	value: 42          →  "type": "number"
//	value: [...]       →  "type": "array"
//	value: null / unset → no type constraint
//	conflicting types  → no type constraint (with a $comment trace)
//
// Conflicts (two controls reading the same path with different
// scalar types) are surfaced as a $comment on the property,
// rather than picking one side. This is a catalog-authoring
// signal worth seeing, not a generator decision to make silently.
//
// Usage:
//
//	go run ./internal/tools/genassetschemas             # write top N schemas
//	go run ./internal/tools/genassetschemas -top 10     # widen the set
//	go run ./internal/tools/genassetschemas -check      # exit 1 if any output is stale
//	go run ./internal/tools/genassetschemas -out PATH   # custom output directory
package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func main() {
	outDir := flag.String("out", "schemas/observation/v1/asset-types", "output directory")
	topN := flag.Int("top", 3, "generate schemas for the top N asset types by declared control count")
	check := flag.Bool("check", false, "check mode: exit 1 if any output is stale")
	flag.Parse()

	controls, err := loadControls()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load controls: %v\n", err)
		os.Exit(1)
	}

	byType := groupByAssetType(controls)
	selected := topNAssetTypes(byType, *topN)
	if len(selected) == 0 {
		fmt.Fprintln(os.Stderr, "no controls declare applicable_asset_types — nothing to generate")
		os.Exit(0)
	}

	if !*check {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", *outDir, err)
			os.Exit(1)
		}
	}

	stale := false
	for _, at := range selected {
		schema := buildSchema(at, byType[at])
		out, err := marshalIndent(schema)
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal %s: %v\n", at, err)
			os.Exit(1)
		}
		path := filepath.Join(*outDir, string(at)+".schema.json")
		if *check {
			existing, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(out)) {
				fmt.Fprintf(os.Stderr, "STALE: %s\n", path)
				stale = true
			}
			continue
		}
		if err := os.WriteFile(path, out, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote %s (%d controls, %d property paths)\n",
			path, len(byType[at]), countProperties(schema))
	}
	if *check && stale {
		fmt.Fprintln(os.Stderr, "FAIL: one or more asset-type schemas are stale; run `make gen-asset-schemas`")
		os.Exit(1)
	}
	if *check {
		fmt.Fprintln(os.Stderr, "OK: all asset-type schemas up to date")
	}
}

func loadControls() ([]policy.ControlDefinition, error) {
	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	return store.All()
}

// groupByAssetType collects every control by each asset type it
// declares as applicable. Controls without an applicable_asset_types
// block are skipped — the generator cannot reason about them.
func groupByAssetType(controls []policy.ControlDefinition) map[kernel.AssetType][]policy.ControlDefinition {
	out := map[kernel.AssetType][]policy.ControlDefinition{}
	for i := range controls {
		for _, at := range controls[i].ApplicableAssetTypes {
			out[at] = append(out[at], controls[i])
		}
	}
	return out
}

// topNAssetTypes returns the top-N asset types sorted by
// (declared_control_count desc, asset_type asc). Ties on count
// resolve alphabetically so the output is stable across runs.
func topNAssetTypes(byType map[kernel.AssetType][]policy.ControlDefinition, n int) []kernel.AssetType {
	keys := make([]kernel.AssetType, 0, len(byType))
	for k := range byType {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b kernel.AssetType) int {
		if d := cmp.Compare(len(byType[b]), len(byType[a])); d != 0 {
			return d
		}
		return cmp.Compare(a, b)
	})
	if n > 0 && len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// pathEntry records what the predicate AST tells us about a
// single property path: the inferred JSON Schema type and the
// control IDs that reference it. Multiple controls may agree
// (no conflict) or disagree (the type is dropped to "any" and
// a $comment surfaces the conflict).
type pathEntry struct {
	Type     string
	Conflict bool
	Sources  []kernel.ControlID
}

// extractPaths walks every control's predicate AST and returns
// a map keyed by dot-separated property path. The returned map's
// keys are sorted later, in the schema emitter.
func extractPaths(controls []policy.ControlDefinition) map[string]*pathEntry {
	out := map[string]*pathEntry{}
	for i := range controls {
		ctl := &controls[i]
		walkPredicate(&ctl.UnsafePredicate, ctl.ID, out)
		walkPredicate(&ctl.ForbiddenState, ctl.ID, out)
	}
	return out
}

func walkPredicate(p *policy.UnsafePredicate, ctlID kernel.ControlID, out map[string]*pathEntry) {
	if p == nil || p.IsEmpty() {
		return
	}
	for i := range p.Any {
		walkRule(&p.Any[i], ctlID, out)
	}
	for i := range p.All {
		walkRule(&p.All[i], ctlID, out)
	}
}

func walkRule(r *policy.PredicateRule, ctlID kernel.ControlID, out map[string]*pathEntry) {
	if !r.Field.IsZero() {
		recordField(r, ctlID, out)
	}
	for i := range r.Any {
		walkRule(&r.Any[i], ctlID, out)
	}
	for i := range r.All {
		walkRule(&r.All[i], ctlID, out)
	}
}

// recordField captures one field reference. The schema-type
// inference depends on the predicate's value: operand: a bool
// value implies the path is a bool, etc. Operators that work on
// containers (list_empty, any_match) leave the type ambiguous;
// they tell us the path exists but not its scalar shape.
func recordField(r *policy.PredicateRule, ctlID kernel.ControlID, out map[string]*pathEntry) {
	path := r.Field.String()
	if path == "" {
		return
	}
	inferred := inferType(r)
	cur, ok := out[path]
	if !ok {
		out[path] = &pathEntry{
			Type:    inferred,
			Sources: []kernel.ControlID{ctlID},
		}
		return
	}
	cur.Sources = append(cur.Sources, ctlID)
	if cur.Conflict {
		return
	}
	// "any" is the no-information case: prefer the more specific
	// type when one side is known.
	switch {
	case cur.Type == "" || cur.Type == "any":
		cur.Type = inferred
	case inferred == "" || inferred == "any":
		// keep existing
	case cur.Type != inferred:
		cur.Conflict = true
		cur.Type = "any"
	}
}

// inferType maps the predicate operator + value pair to a JSON
// Schema type string. Operators like "missing" / "present" /
// "list_empty" / "any_match" tell us about containment, not
// scalar shape — those return "" so the schema doesn't constrain
// the field's type.
func inferType(r *policy.PredicateRule) string {
	switch r.Op {
	case "missing", "present":
		return ""
	case "list_empty", "any_match", "any_identity_match", "any_in_field", "not_in_field", "contains", "not_subset_of_field", "neq_field":
		// These read containers; the value: side carries the
		// element-shape, which is too coarse to translate
		// reliably without a per-operator emitter.
		return ""
	}
	switch r.Value.Raw().(type) {
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64, int, int64, float32:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return ""
}

// buildSchema converts the path map into a nested JSON Schema
// document. Dot-separated paths become nested object properties.
// Each leaf carries:
//
//	"type":        the inferred type (omitted when ambiguous)
//	"description": auto-generated provenance (control count)
//	"$comment":    set only when a conflict was detected
//
// additionalProperties: true is set at every level — Stave reads
// what it reads, but a collector may emit more, and the schema's
// job is to validate Stave's needs, not to constrain the
// collector. See observation-contract-audit.md for the design
// rationale.
func buildSchema(at kernel.AssetType, controls []policy.ControlDefinition) map[string]any {
	paths := extractPaths(controls)

	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	root := newObjectNode()
	for _, k := range keys {
		// Predicate paths land under properties.<...>; strip the
		// leading "properties." prefix since the schema we emit
		// describes the value of asset.properties, not the asset
		// envelope.
		path := strings.TrimPrefix(k, "properties.")
		if path == k {
			// Some predicate paths reference asset envelope
			// fields (e.g. "vendor"). Those don't belong in the
			// per-asset-type property schema; skip.
			continue
		}
		insertPath(root, strings.Split(path, "."), paths[k])
	}

	return map[string]any{
		"$schema":              "https://json-schema.org/draft/2020-12/schema",
		"$id":                  fmt.Sprintf("urn:stave:schema:asset-type:%s", at),
		"title":                fmt.Sprintf("%s Properties", at),
		"description":          fmt.Sprintf("Property schema for %s observations. %d controls declare applicable_asset_types for this type. Generated from the embedded control catalog — do not edit by hand.", at, len(controls)),
		"type":                 "object",
		"additionalProperties": true,
		"properties":           root["properties"],
	}
}

func newObjectNode() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": true,
		"properties":           map[string]any{},
	}
}

// insertPath walks the segments of a dot-path, creating nested
// object nodes as needed, and attaches the leaf type/metadata at
// the final segment.
func insertPath(node map[string]any, segments []string, leaf *pathEntry) {
	cur := node
	for i, seg := range segments {
		props := cur["properties"].(map[string]any)
		existing, ok := props[seg].(map[string]any)
		if !ok {
			existing = map[string]any{}
			props[seg] = existing
		}
		if i == len(segments)-1 {
			applyLeaf(existing, leaf)
			return
		}
		// Mid-path: must be an object node. If a prior leaf
		// landed here as a scalar, promote it to an object that
		// also carries the original scalar type via $comment.
		if _, isObj := existing["type"]; !isObj {
			existing["type"] = "object"
			existing["additionalProperties"] = true
			existing["properties"] = map[string]any{}
		} else if existing["type"] != "object" {
			existing["$comment"] = fmt.Sprintf(
				"path used as both a %s scalar and an object container by different controls; treating as object here",
				existing["type"],
			)
			existing["type"] = "object"
			existing["additionalProperties"] = true
			if _, hasProps := existing["properties"]; !hasProps {
				existing["properties"] = map[string]any{}
			}
		}
		cur = existing
	}
}

func applyLeaf(node map[string]any, leaf *pathEntry) {
	// Don't overwrite a node that's already been promoted to an
	// object container during a deeper-path insertion.
	if existing, ok := node["type"]; ok && existing == "object" {
		return
	}
	if leaf.Type != "" {
		node["type"] = leaf.Type
	}
	descSources := dedupAndSort(leaf.Sources)
	if len(descSources) > 3 {
		node["description"] = fmt.Sprintf("Read by %d controls: %s, %s, %s, …",
			len(descSources), descSources[0], descSources[1], descSources[2])
	} else if len(descSources) > 0 {
		quoted := make([]string, len(descSources))
		for i, s := range descSources {
			quoted[i] = string(s)
		}
		node["description"] = "Read by control(s): " + strings.Join(quoted, ", ")
	}
	if leaf.Conflict {
		node["$comment"] = "type conflict across controls; constraint dropped — investigate catalog inconsistency"
	}
}

func dedupAndSort(ids []kernel.ControlID) []kernel.ControlID {
	seen := map[kernel.ControlID]struct{}{}
	out := make([]kernel.ControlID, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

func countProperties(schema map[string]any) int {
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return 0
	}
	return countNested(props)
}

func countNested(node map[string]any) int {
	count := 0
	for _, v := range node {
		obj, ok := v.(map[string]any)
		if !ok {
			continue
		}
		count++
		if inner, ok := obj["properties"].(map[string]any); ok {
			count += countNested(inner)
		}
	}
	return count
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
