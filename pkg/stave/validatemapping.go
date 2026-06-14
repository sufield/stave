package stave

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	contractschema "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predindex"
)

// mappingDoc mirrors the documented structure of contracts/steampipe/*.yaml.
// Unknown fields are tolerated (no DisallowUnknownFields) because the
// mapping format is documented to grow.
type mappingDoc struct {
	AssetType               string             `yaml:"asset_type"`
	SteampipeTable          string             `yaml:"steampipe_table"`
	SchemaVersion           string             `yaml:"schema_version"`
	AssetIDColumn           string             `yaml:"asset_id_column"`
	AssetIDFallbackTemplate string             `yaml:"asset_id_fallback_template"`
	Vendor                  string             `yaml:"vendor"`
	Operations              []mappingOperation `yaml:"operations"`
}

type mappingOperation struct {
	Kind       string   `yaml:"kind"`
	Path       string   `yaml:"path"`
	Column     string   `yaml:"column"`
	Value      any      `yaml:"value"`
	JSONPath   string   `yaml:"json_path"`
	Op         string   `yaml:"op"`
	Inputs     []string `yaml:"inputs"`
	Coerce     string   `yaml:"coerce"`
	UseAssetID bool     `yaml:"use_asset_id"`
}

type mappingReport struct {
	File          string           `json:"file"`
	AssetType     string           `json:"asset_type"`
	SchemaPath    string           `json:"schema_path,omitempty"`
	HasSchema     bool             `json:"has_schema"`
	Operations    mappingOpCounts  `json:"operations"`
	Structural    []mappingFinding `json:"structural"`
	Schema        []mappingFinding `json:"schema"`
	Coverage      mappingCoverage  `json:"coverage"`
	OverallStatus string           `json:"overall_status"`
}

type mappingOpCounts struct {
	Total  int            `json:"total"`
	ByKind map[string]int `json:"by_kind"`
}

type mappingFinding struct {
	Severity string `json:"severity"` // error | warning
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type mappingCoverage struct {
	CatalogPaths     int                  `json:"catalog_paths"`
	Populated        int                  `json:"populated_paths"`
	PercentPopulated float64              `json:"percent_populated"`
	UnpopulatedTop   []mappingUnpopulated `json:"unpopulated_top"`
}

type mappingUnpopulated struct {
	Path     string `json:"path"`
	Controls int    `json:"controls"`
	Chains   int    `json:"chains"`
}

// ValidateMapping validates a Steampipe→Stave mapping (raw YAML for the
// file at path) against the structural contract, the per-asset JSON
// Schema, and the control+chain catalog's read surface, and renders the
// report in the requested format ("json" or "text"/""). It returns the
// rendered bytes and whether the mapping is INVALID (the caller maps that
// to exit 3 — the report is still rendered). A YAML parse failure wraps
// [ErrInvalidInput] (exit 2); loader failures stay plain (exit 4). It is
// the library entry point behind `stave validate-mapping`.
func ValidateMapping(ctx context.Context, file string, raw []byte, controlsDir, chainsDir, format string, strict bool) ([]byte, bool, error) {
	var m mappingDoc
	if parseErr := yaml.Unmarshal(raw, &m); parseErr != nil {
		return nil, false, fmt.Errorf("parse %s: %w: %w", file, parseErr, ErrInvalidInput)
	}

	r := mappingReport{
		File:      file,
		AssetType: m.AssetType,
		Operations: mappingOpCounts{
			Total:  len(m.Operations),
			ByKind: mappingTallyKinds(m.Operations),
		},
	}

	r.Structural = mappingStructuralFindings(m)

	schemaBytes, schemaErr := contractschema.AssetTypeSchema(m.AssetType)
	if schemaErr == nil {
		r.HasSchema = true
		r.SchemaPath = fmt.Sprintf("schemas/observation/v1/asset-types/%s.schema.json", m.AssetType)
		r.Schema = mappingSchemaFindings(m, schemaBytes)
	} else if m.AssetType != "" {
		r.Schema = []mappingFinding{{
			Severity: "warning",
			Message:  fmt.Sprintf("no per-asset schema registered for %q — path checks skipped", m.AssetType),
		}}
	}

	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return nil, false, err
	}
	chains, err := loadChainsOptional(chainsDir)
	if err != nil {
		return nil, false, err
	}
	idx := predindex.Build(controls, chains)
	r.Coverage = mappingCoverageReport(m, idx)

	r.OverallStatus = mappingOverallStatus(r, strict)

	out, err := renderMappingReport(r, format)
	if err != nil {
		return nil, false, err
	}
	return out, r.OverallStatus == "INVALID", nil
}

func renderMappingReport(r mappingReport, format string) ([]byte, error) {
	var buf bytes.Buffer
	if format == "json" {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return nil, fmt.Errorf("render validation report: %w", err)
		}
	} else {
		if err := writeMappingValidationText(&buf, r); err != nil {
			return nil, fmt.Errorf("render validation report: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func mappingTallyKinds(ops []mappingOperation) map[string]int {
	out := map[string]int{}
	for i := range ops {
		out[ops[i].Kind]++
	}
	return out
}

// mappingStructuralFindings flags missing required fields and malformed
// operations. Each kind's required subfields: field — column; static —
// value; extract — column, json_path; computed — op (any|all), inputs.
func mappingStructuralFindings(m mappingDoc) []mappingFinding {
	var out []mappingFinding
	if m.AssetType == "" {
		out = append(out, mappingFinding{Severity: "error", Message: "missing required field: asset_type"})
	}
	if m.AssetIDColumn == "" {
		out = append(out, mappingFinding{Severity: "error", Message: "missing required field: asset_id_column"})
	}
	if len(m.Operations) == 0 {
		out = append(out, mappingFinding{Severity: "error", Message: "missing required field: operations (must be non-empty)"})
	}

	knownKinds := map[string]struct{}{
		"field": {}, "static": {}, "extract": {}, "computed": {},
	}
	for i := range m.Operations {
		op := &m.Operations[i]
		opLabel := fmt.Sprintf("operations[%d]", i)
		if op.Kind == "" {
			out = append(out, mappingFinding{Severity: "error", Path: opLabel, Message: "missing kind"})
			continue
		}
		if _, ok := knownKinds[op.Kind]; !ok {
			out = append(out, mappingFinding{
				Severity: "error", Path: opLabel,
				Message: fmt.Sprintf("unknown kind %q (want field | static | extract | computed)", op.Kind),
			})
			continue
		}
		if op.Path == "" {
			out = append(out, mappingFinding{Severity: "error", Path: opLabel, Message: "missing path"})
		}
		switch op.Kind {
		case "field":
			if op.Column == "" {
				out = append(out, mappingFinding{
					Severity: "error", Path: opLabel,
					Message: "field operation requires column",
				})
			}
		case "static":
			if op.Value == nil {
				out = append(out, mappingFinding{
					Severity: "error", Path: opLabel,
					Message: "static operation requires value",
				})
			}
		case "extract":
			if op.Column == "" {
				out = append(out, mappingFinding{
					Severity: "error", Path: opLabel,
					Message: "extract operation requires column",
				})
			}
			if op.JSONPath == "" {
				out = append(out, mappingFinding{
					Severity: "error", Path: opLabel,
					Message: "extract operation requires json_path",
				})
			}
		case "computed":
			if op.Op != "any" && op.Op != "all" {
				out = append(out, mappingFinding{
					Severity: "error", Path: opLabel,
					Message: fmt.Sprintf("computed operation requires op: any | all (got %q)", op.Op),
				})
			}
			if len(op.Inputs) == 0 {
				out = append(out, mappingFinding{
					Severity: "error", Path: opLabel,
					Message: "computed operation requires non-empty inputs",
				})
			}
		}
	}
	return out
}

// mappingSchemaFindings checks every operation path against the per-asset
// JSON Schema's declared property tree. additionalProperties:true means
// undeclared paths still parse, so they surface as warnings, not errors.
func mappingSchemaFindings(m mappingDoc, schemaBytes []byte) []mappingFinding {
	var doc map[string]any
	if err := json.Unmarshal(schemaBytes, &doc); err != nil {
		return []mappingFinding{{Severity: "error", Message: "failed to parse asset schema: " + err.Error()}}
	}
	var out []mappingFinding
	for i := range m.Operations {
		op := &m.Operations[i]
		if op.Path == "" {
			continue
		}
		if !pathDeclaredInSchema(doc, op.Path) {
			out = append(out, mappingFinding{
				Severity: "warning",
				Path:     fmt.Sprintf("operations[%d]", i),
				Message:  fmt.Sprintf("path %q is not declared in the asset schema (no control reads it)", op.Path),
			})
		}
	}
	return out
}

// pathDeclaredInSchema returns true when each dot segment of path (after
// the leading "properties.") is declared under nested `properties` blocks.
func pathDeclaredInSchema(schema map[string]any, path string) bool {
	const prefix = "properties."
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	cursor := schema
	p := strings.TrimPrefix(path, prefix)
	for p != "" {
		var seg string
		seg, p, _ = strings.Cut(p, ".")
		props, ok := cursor["properties"].(map[string]any)
		if !ok {
			return false
		}
		next, ok := props[seg].(map[string]any)
		if !ok {
			return false
		}
		cursor = next
	}
	return true
}

// mappingCoverageReport measures how many catalog-read paths for this asset
// type the mapping populates.
func mappingCoverageReport(m mappingDoc, idx predindex.Index) mappingCoverage {
	at := kernel.AssetType(m.AssetType)
	catalogPaths := idx.TypeToPaths[at]
	populated := map[string]struct{}{}
	for i := range m.Operations {
		populated[m.Operations[i].Path] = struct{}{}
	}

	hits := 0
	type gap struct {
		path     string
		controls int
		chains   int
	}
	var gaps []gap
	for _, p := range catalogPaths {
		if _, ok := populated[p]; ok {
			hits++
			continue
		}
		gaps = append(gaps, gap{
			path:     p,
			controls: len(idx.PathToControls[p]),
			chains:   len(idx.PathToChains[p]),
		})
	}
	slices.SortFunc(gaps, func(a, b gap) int {
		return cmp.Or(
			cmp.Compare(b.controls, a.controls),
			cmp.Compare(b.chains, a.chains),
			cmp.Compare(a.path, b.path),
		)
	})
	top := gaps
	if len(top) > 5 {
		top = top[:5]
	}
	out := mappingCoverage{
		CatalogPaths:   len(catalogPaths),
		Populated:      hits,
		UnpopulatedTop: make([]mappingUnpopulated, 0, len(top)),
	}
	if len(catalogPaths) > 0 {
		out.PercentPopulated = float64(hits) / float64(len(catalogPaths)) * 100
	}
	for _, g := range top {
		out.UnpopulatedTop = append(out.UnpopulatedTop, mappingUnpopulated{
			Path: g.path, Controls: g.controls, Chains: g.chains,
		})
	}
	return out
}

// mappingOverallStatus folds structural errors, schema warnings, and
// coverage gaps into a single status. Structural errors always fail;
// schema warnings and coverage gaps fail only under --strict.
func mappingOverallStatus(r mappingReport, strict bool) string {
	for _, f := range r.Structural {
		if f.Severity == "error" {
			return "INVALID"
		}
	}
	if strict {
		for _, f := range r.Schema {
			if f.Severity == "warning" || f.Severity == "error" {
				return "INVALID"
			}
		}
		if r.Coverage.CatalogPaths > 0 && r.Coverage.Populated < r.Coverage.CatalogPaths {
			return "INVALID"
		}
	}
	return "VALID"
}

func writeMappingValidationText(w io.Writer, r mappingReport) error {
	fmt.Fprintf(w, "Mapping:    %s\n", r.File)
	fmt.Fprintf(w, "Asset type: %s\n", r.AssetType)
	if r.HasSchema {
		fmt.Fprintf(w, "Schema:     %s\n", r.SchemaPath)
	} else {
		fmt.Fprintf(w, "Schema:     (none registered for this asset type)\n")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Operations:")
	kinds := sortedKeys(r.Operations.ByKind)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, k := range kinds {
		fmt.Fprintf(tw, "  %s\t%d\n", k, r.Operations.ByKind[k])
	}
	fmt.Fprintf(tw, "  total\t%d\n", r.Operations.Total)
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush operations table: %w", err)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Structural:")
	if len(r.Structural) == 0 {
		fmt.Fprintln(w, "  ok")
	} else {
		for _, f := range r.Structural {
			renderMappingFinding(w, f)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Schema fit:")
	if !r.HasSchema {
		fmt.Fprintln(w, "  skipped — no per-asset schema")
	} else if len(r.Schema) == 0 {
		fmt.Fprintln(w, "  ok")
	} else {
		for _, f := range r.Schema {
			renderMappingFinding(w, f)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Catalog coverage:")
	c := r.Coverage
	if c.CatalogPaths == 0 {
		fmt.Fprintln(w, "  catalog reads no paths for this asset type")
	} else {
		fmt.Fprintf(w, "  catalog reads %d paths; mapping populates %d (%.0f%%)\n",
			c.CatalogPaths, c.Populated, c.PercentPopulated)
		if len(c.UnpopulatedTop) > 0 {
			fmt.Fprintln(w, "  top unpopulated paths:")
			gw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			for _, g := range c.UnpopulatedTop {
				fmt.Fprintf(gw, "    %s\t%d controls\t%d chains\n", g.Path, g.Controls, g.Chains)
			}
			if err := gw.Flush(); err != nil {
				return fmt.Errorf("flush coverage table: %w", err)
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Result: %s\n", r.OverallStatus)
	return nil
}

func renderMappingFinding(w io.Writer, f mappingFinding) {
	marker := "WARN"
	if f.Severity == "error" {
		marker = "ERR "
	}
	if f.Path != "" {
		fmt.Fprintf(w, "  %s  %s: %s\n", marker, f.Path, f.Message)
	} else {
		fmt.Fprintf(w, "  %s  %s\n", marker, f.Message)
	}
}
