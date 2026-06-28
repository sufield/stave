// Package transform converts raw AWS CLI snapshots (e.g. `aws iam list-roles`
// output) into obs.v0.1 observations using jq filters run in-process via gojq.
//
// This is an AWS adapter: it lives under internal/adapters/aws and never imports
// internal/core. Collection (calling AWS) stays the user's job; this package only
// reshapes already-captured JSON, matching the discover→collect→transform→apply
// workflow.
//
// Iteration 0 seeds the gojq primitive (runJQ) and its test. The detector,
// scrubber, obs.v0.1 envelope, schema validation, and the .jq filter files
// (extracted from scripts/aws-snapshot.sh — the single source of truth for the
// mappings) land in Iteration 1.
package transform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/itchyny/gojq"

	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
)

// Options configures a transform run. Account supplies the AWS account ID for
// filters whose raw input carries no ARN (e.g. the account password policy).
// CapturedAt and Source populate the obs.v0.1 envelope; both should be set
// explicitly for deterministic output.
type Options struct {
	Account    string
	CapturedAt string // RFC3339, e.g. 2026-06-01T12:00:00Z
	Source     string // obs.v0.1 source field; defaults to "deployed"
}

// Stats reports what a transform run did.
type Stats struct {
	Files   int // raw documents seen
	Skipped int // documents whose top-level key matched no filter
	Assets  int // obs.v0.1 assets produced
}

// TransformFiles converts raw AWS CLI documents (filename → bytes) into one
// validated obs.v0.1 observation document. Files whose shape no filter
// recognizes are skipped (counted in Stats.Skipped), not fatal. The result is
// validated against the obs.v0.1 schema before return — a schema failure is an
// error, never silently emitted.
func TransformFiles(files map[string][]byte, opts Options) ([]byte, Stats, error) {
	var stats Stats
	assets := []json.RawMessage{} // non-nil so an all-skipped run still marshals "assets": []

	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	// Phase 1: parse, derive a filename key if needed, detect the filter, and
	// categorize. Skipped files (no matching filter) are counted, not fatal.
	type pendingDoc struct {
		name, filter string
		parsed       map[string]any
		category     int
	}
	var docs []pendingDoc
	for _, name := range names {
		stats.Files++
		// An empty / whitespace-only file is skipped, not fatal: a collector
		// commonly leaves an empty file for a resource that returned nothing. A
		// non-empty file that won't parse is corrupt data and fails loud.
		if len(bytes.TrimSpace(files[name])) == 0 {
			stats.Skipped++
			continue
		}
		var parsed map[string]any
		if err := json.Unmarshal(files[name], &parsed); err != nil {
			return nil, stats, fmt.Errorf("transform %s: parse raw JSON: %w", name, err)
		}
		injectFilenameKey(name, parsed)
		filter, ok := detectFilter(parsed)
		if !ok {
			stats.Skipped++
			continue
		}
		docs = append(docs, pendingDoc{name, filter, parsed, filterCategory(filter)})
	}

	// Merge order is by CATEGORY, not filename: base assets must be created
	// before enrichments deep-merge their fields on top, otherwise a base
	// default could overwrite an enrichment (e.g. "group-inline-*.json" sorts
	// before "iam_groups.json"). base -> self-describing -> enrichment, then name.
	sort.SliceStable(docs, func(i, j int) bool {
		if docs[i].category != docs[j].category {
			return docs[i].category < docs[j].category
		}
		return docs[i].name < docs[j].name
	})

	// Phase 2: run each filter and scrub its output.
	for _, d := range docs {
		fileAssets, err := runFilter(d.filter, d.parsed, opts)
		if err != nil {
			return nil, stats, fmt.Errorf("transform %s: %w", d.name, err)
		}
		assets = append(assets, fileAssets...)
	}

	// Cross-call merge: one AWS resource is often spread across several API calls
	// (a bucket's list-buckets entry + its public-access-block + its encryption).
	// Each filter emits an object carrying the resource `id`; objects sharing an
	// id are deep-merged into one asset here, with later (enrichment) fields
	// winning over earlier (base) ones.
	merged, err := mergeByID(assets)
	if err != nil {
		return nil, stats, err
	}
	assets = merged
	stats.Assets = len(assets)

	source := opts.Source
	if source == "" {
		source = "deployed"
	}
	envelope := map[string]any{
		"schema_version": "obs.v0.1",
		"captured_at":    opts.CapturedAt,
		"source":         source,
		"generated_by": map[string]any{
			"source_type":  "aws.cli",
			"tool":         "stave-transform",
			"tool_version": "0.1.0",
		},
		"assets": assets,
	}
	out, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, stats, fmt.Errorf("marshal observation: %w", err)
	}

	issues, err := contractvalidator.New().ValidateObservationJSON(out)
	if err != nil {
		return nil, stats, fmt.Errorf("validate observation: %w", err)
	}
	if issues.Failed() {
		return nil, stats, fmt.Errorf("transform produced an invalid obs.v0.1 document: %w", issues)
	}
	return out, stats, nil
}

// mergeByID deep-merges asset objects that share the same `id`, preserving
// first-seen order. This is the cross-call merge: a base filter and one or more
// enrichment filters each emit an object with the resource id; the result is one
// asset combining all their fields. An object with no id is kept as-is (it can
// still be a valid standalone asset for schemas that don't require id).
func mergeByID(assets []json.RawMessage) ([]json.RawMessage, error) {
	order := make([]string, 0, len(assets))
	byID := make(map[string]map[string]any, len(assets))
	var passthrough []json.RawMessage

	for _, raw := range assets {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("merge: parse asset: %w", err)
		}
		id, _ := m["id"].(string)
		if id == "" {
			passthrough = append(passthrough, raw)
			continue
		}
		if existing, ok := byID[id]; ok {
			deepMerge(existing, m)
			continue
		}
		byID[id] = m
		order = append(order, id)
	}

	out := make([]json.RawMessage, 0, len(order)+len(passthrough))
	for _, id := range order {
		b, err := json.Marshal(byID[id])
		if err != nil {
			return nil, fmt.Errorf("merge: re-marshal asset %q: %w", id, err)
		}
		out = append(out, b)
	}
	return append(out, passthrough...), nil
}

// deepMerge recursively merges src into dst: nested objects merge key-by-key;
// scalars and arrays from src overwrite dst (last writer wins). Used only to
// combine fragments of the SAME asset, so overwrite is the right semantics —
// an enrichment that re-states a field is authoritative for it.
func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if srcMap, ok := v.(map[string]any); ok {
			if dstMap, ok := dst[k].(map[string]any); ok {
				deepMerge(dstMap, srcMap)
				continue
			}
		}
		dst[k] = v
	}
}

// runFilter runs a detected filter over a parsed document and scrubs each
// produced asset.
func runFilter(filterName string, parsed map[string]any, opts Options) ([]json.RawMessage, error) {
	program, err := filterProgram(filterName)
	if err != nil {
		return nil, err
	}
	out, err := runJQWithArgs(program, parsed, map[string]any{"account": opts.Account})
	if err != nil {
		return nil, err
	}
	assets := make([]json.RawMessage, 0, len(out))
	for _, a := range out {
		var node any
		if err := json.Unmarshal(a, &node); err != nil {
			return nil, fmt.Errorf("parse filter output: %w", err)
		}
		scrubAsset(node)
		scrubbed, err := json.Marshal(node)
		if err != nil {
			return nil, fmt.Errorf("re-marshal scrubbed asset: %w", err)
		}
		assets = append(assets, scrubbed)
	}
	return assets, nil
}

// runJQ compiles a jq program and runs it over a single decoded JSON document,
// returning every emitted value as raw JSON. A jq runtime error (e.g. indexing a
// string) surfaces as an error rather than a partial result — fail loud.
func runJQ(program string, input any) ([]json.RawMessage, error) {
	return runJQWithArgs(program, input, nil)
}

// runJQWithArgs is runJQ with named jq variables ($name) bound from args — used
// for capture-time parameters that aren't in the raw AWS output (e.g. the account
// ID, which aws-snapshot.sh supplies at capture time). Keys are bare names; the
// filter references them as $name.
func runJQWithArgs(program string, input any, args map[string]any) ([]json.RawMessage, error) {
	names := make([]string, 0, len(args))
	values := make([]any, 0, len(args))
	for k, v := range args {
		names = append(names, "$"+k)
		values = append(values, v)
	}

	query, err := gojq.Parse(program)
	if err != nil {
		return nil, fmt.Errorf("parse jq filter: %w", err)
	}
	code, err := gojq.Compile(query, gojq.WithVariables(names))
	if err != nil {
		return nil, fmt.Errorf("compile jq filter: %w", err)
	}

	var out []json.RawMessage
	iter := code.Run(input, values...)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if e, isErr := v.(error); isErr {
			return nil, fmt.Errorf("run jq filter: %w", e)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal jq output: %w", err)
		}
		out = append(out, b)
	}
	return out, nil
}
