// Package validatemapping implements `stave validate-mapping` — a
// pre-flight check for Steampipe→Stave transform contracts. It
// answers three questions about a mapping file before an agent uses
// it to populate observations:
//
//  1. Structural: required fields present, operation kinds recognised,
//     each kind has its mandatory subfields.
//  2. Schema fit: every operation path points to a property the
//     per-asset JSON Schema declares (or warns when the schema does
//     not register that path — `additionalProperties: true` would
//     accept it but no control reads it).
//  3. Catalog coverage: how many of the property paths the control
//     catalog actually reads for this asset type are populated by the
//     mapping, and which high-control-count paths are missing.
//
// The command does not execute the mapping. Authoring-time validation
// only — the YAML interpreter lives in examples/agents/stave_transform.py
// and runs at observation-build time. Use this to catch typos, missing
// operations, and coverage holes before the agent ships a snapshot.
package validatemapping

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	contractschema "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predindex"
)

// Deps holds the catalog-loading factories.
type Deps struct {
	NewCtlRepo     compose.CtlRepoFactory
	NewChainLoader compose.ChainLoaderFactory
}

type options struct {
	File        string
	ControlsDir string
	ChainsDir   string
	Format      string
	Strict      bool
}

// NewCmd constructs the `validate-mapping` command.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{
		Format:      "text",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	cmd := &cobra.Command{
		Use:   "validate-mapping",
		Short: "Validate a Steampipe→Stave mapping file before use",
		Long: `Validate inspects a contracts/steampipe/<asset_type>.yaml mapping and
reports whether it can produce a schema-valid observation for the
declared asset type, plus how much of the catalog's read surface it
covers.

Three checks:
  1. Structural — required fields, recognised operation kinds, each
     kind's mandatory subfields.
  2. Schema fit — every operation path resolves to a property declared
     in schemas/observation/v1/asset-types/<asset_type>.schema.json
     (paths the schema does not declare are warned, not failed —
     additionalProperties is true).
  3. Catalog coverage — how many of the property paths the control +
     chain catalog reads for this asset type are populated, with the
     highest-control-count gaps surfaced.

Inputs:
  --file FILE        Mapping YAML to validate (required)
  --controls DIR     Control catalog (default: controls)
  --chains DIR       Chain catalog (default: chains)
  --format F         text (default) | json
  --strict           Treat coverage gaps and unknown-to-schema paths
                     as failures (exit 3) instead of warnings.

Exit codes:
  0   Mapping is valid (warnings may apply unless --strict)
  2   Invalid input (missing flag, unreadable file, bad format)
  3   Mapping is invalid (structural or, with --strict, coverage gap)
  4   Internal error
`,
		Example: `  stave validate-mapping --file contracts/steampipe/aws_s3_bucket.yaml
  stave validate-mapping --file contracts/steampipe/aws_iam_role.yaml --strict
  stave validate-mapping --file contracts/steampipe/aws_kms_key.yaml --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}
	cmd.Flags().StringVar(&opts.File, "file", "", "mapping YAML file to validate (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().BoolVar(&opts.Strict, "strict", false, "treat coverage gaps and unknown-to-schema paths as failures")
	return cmd
}

// mapping mirrors the documented structure of contracts/steampipe/*.yaml.
// Unknown fields are tolerated (no DisallowUnknownFields) because the
// mapping format is documented to grow; new fields should fail
// structural checks only when this validator is updated to require them.
type mapping struct {
	AssetType               string      `yaml:"asset_type"`
	SteampipeTable          string      `yaml:"steampipe_table"`
	SchemaVersion           string      `yaml:"schema_version"`
	AssetIDColumn           string      `yaml:"asset_id_column"`
	AssetIDFallbackTemplate string      `yaml:"asset_id_fallback_template"`
	Vendor                  string      `yaml:"vendor"`
	Operations              []operation `yaml:"operations"`
}

type operation struct {
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

type report struct {
	File          string    `json:"file"`
	AssetType     string    `json:"asset_type"`
	SchemaPath    string    `json:"schema_path,omitempty"`
	HasSchema     bool      `json:"has_schema"`
	Operations    opCounts  `json:"operations"`
	Structural    []finding `json:"structural"`
	Schema        []finding `json:"schema"`
	Coverage      coverage  `json:"coverage"`
	OverallStatus string    `json:"overall_status"`
}

type opCounts struct {
	Total  int            `json:"total"`
	ByKind map[string]int `json:"by_kind"`
}

type finding struct {
	Severity string `json:"severity"` // error | warning
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
}

type coverage struct {
	CatalogPaths     int           `json:"catalog_paths"`
	Populated        int           `json:"populated_paths"`
	PercentPopulated float64       `json:"percent_populated"`
	UnpopulatedTop   []unpopulated `json:"unpopulated_top"`
}

type unpopulated struct {
	Path     string `json:"path"`
	Controls int    `json:"controls"`
	Chains   int    `json:"chains"`
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	if strings.TrimSpace(opts.File) == "" {
		return &ui.UserError{Err: errors.New("--file is required")}
	}
	switch opts.Format {
	case "text", "json":
	default:
		return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
	}

	raw, err := os.ReadFile(opts.File)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read %s: %w", opts.File, err)}
	}

	var m mapping
	if parseErr := yaml.Unmarshal(raw, &m); parseErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse %s: %w", opts.File, parseErr)}
	}

	r := report{
		File:      opts.File,
		AssetType: m.AssetType,
		Operations: opCounts{
			Total:  len(m.Operations),
			ByKind: tallyKinds(m.Operations),
		},
	}

	r.Structural = structuralFindings(m)

	schemaBytes, schemaErr := contractschema.AssetTypeSchema(m.AssetType)
	if schemaErr == nil {
		r.HasSchema = true
		r.SchemaPath = fmt.Sprintf("schemas/observation/v1/asset-types/%s.schema.json", m.AssetType)
		r.Schema = schemaFindings(m, schemaBytes)
	} else if m.AssetType != "" {
		r.Schema = []finding{{
			Severity: "warning",
			Message:  fmt.Sprintf("no per-asset schema registered for %q — path checks skipped", m.AssetType),
		}}
	}

	controls, err := compose.LoadControlsFrom(ctx, deps.NewCtlRepo, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}
	chains, err := compose.LoadChainDefinitions(ctx, deps.NewChainLoader, opts.ChainsDir)
	if err != nil {
		var notFound interface{ NotFound() bool }
		if !errors.As(err, &notFound) || !notFound.NotFound() {
			return fmt.Errorf("load chains: %w", err)
		}
		chains = nil
	}
	idx := predindex.Build(controls, chains)
	r.Coverage = coverageReport(m, idx)

	r.OverallStatus = overall(r, opts.Strict)

	if opts.Format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return err
		}
	} else if err := writeText(w, r); err != nil {
		return err
	}

	if r.OverallStatus == "INVALID" {
		return fmt.Errorf("mapping %s failed validation: %w", opts.File, ui.ErrDiagnosticsFound)
	}
	return nil
}

func tallyKinds(ops []operation) map[string]int {
	out := map[string]int{}
	for i := range ops {
		out[ops[i].Kind]++
	}
	return out
}

// structuralFindings flags missing required fields and malformed
// operations. Each kind's required subfields:
//
//	field    — column
//	static   — value
//	extract  — column, json_path
//	computed — op (any|all), inputs (non-empty)
func structuralFindings(m mapping) []finding {
	var out []finding
	if m.AssetType == "" {
		out = append(out, finding{Severity: "error", Message: "missing required field: asset_type"})
	}
	if m.AssetIDColumn == "" {
		out = append(out, finding{Severity: "error", Message: "missing required field: asset_id_column"})
	}
	if len(m.Operations) == 0 {
		out = append(out, finding{Severity: "error", Message: "missing required field: operations (must be non-empty)"})
	}

	knownKinds := map[string]struct{}{
		"field": {}, "static": {}, "extract": {}, "computed": {},
	}
	for i := range m.Operations {
		op := &m.Operations[i]
		opLabel := fmt.Sprintf("operations[%d]", i)
		if op.Kind == "" {
			out = append(out, finding{Severity: "error", Path: opLabel, Message: "missing kind"})
			continue
		}
		if _, ok := knownKinds[op.Kind]; !ok {
			out = append(out, finding{
				Severity: "error", Path: opLabel,
				Message: fmt.Sprintf("unknown kind %q (want field | static | extract | computed)", op.Kind),
			})
			continue
		}
		if op.Path == "" {
			out = append(out, finding{Severity: "error", Path: opLabel, Message: "missing path"})
		}
		switch op.Kind {
		case "field":
			if op.Column == "" {
				out = append(out, finding{
					Severity: "error", Path: opLabel,
					Message: "field operation requires column",
				})
			}
		case "static":
			if op.Value == nil {
				out = append(out, finding{
					Severity: "error", Path: opLabel,
					Message: "static operation requires value",
				})
			}
		case "extract":
			if op.Column == "" {
				out = append(out, finding{
					Severity: "error", Path: opLabel,
					Message: "extract operation requires column",
				})
			}
			if op.JSONPath == "" {
				out = append(out, finding{
					Severity: "error", Path: opLabel,
					Message: "extract operation requires json_path",
				})
			}
		case "computed":
			if op.Op != "any" && op.Op != "all" {
				out = append(out, finding{
					Severity: "error", Path: opLabel,
					Message: fmt.Sprintf("computed operation requires op: any | all (got %q)", op.Op),
				})
			}
			if len(op.Inputs) == 0 {
				out = append(out, finding{
					Severity: "error", Path: opLabel,
					Message: "computed operation requires non-empty inputs",
				})
			}
		}
	}
	return out
}

// schemaFindings checks every operation path against the per-asset
// JSON Schema's declared property tree. Paths use the
// "properties.<segment>.<segment>..." form; we walk the schema's
// nested `properties` map to verify each segment is declared. The
// schema's additionalProperties:true means undeclared paths would
// still parse — but no control reads them, so we surface them as
// warnings the agent can act on.
func schemaFindings(m mapping, schemaBytes []byte) []finding {
	var doc map[string]any
	if err := json.Unmarshal(schemaBytes, &doc); err != nil {
		return []finding{{Severity: "error", Message: "failed to parse asset schema: " + err.Error()}}
	}
	var out []finding
	for i := range m.Operations {
		op := &m.Operations[i]
		if op.Path == "" {
			continue
		}
		if !pathDeclaredInSchema(doc, op.Path) {
			out = append(out, finding{
				Severity: "warning",
				Path:     fmt.Sprintf("operations[%d]", i),
				Message:  fmt.Sprintf("path %q is not declared in the asset schema (no control reads it)", op.Path),
			})
		}
	}
	return out
}

// pathDeclaredInSchema returns true when each dot segment of path
// (after the leading "properties.") is declared under nested
// `properties` blocks. Returns true if a parent has
// additionalProperties:true AND no nested properties of its own — the
// schema permits anything past that point.
func pathDeclaredInSchema(schema map[string]any, path string) bool {
	const prefix = "properties."
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	segs := strings.Split(strings.TrimPrefix(path, prefix), ".")
	cursor := schema
	for _, seg := range segs {
		props, ok := cursor["properties"].(map[string]any)
		if !ok {
			// No properties declared at this level — the schema
			// permits anything (additionalProperties default or true)
			// but does not record the segment as known.
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

// coverageReport measures how many catalog-read paths for this asset
// type the mapping populates. The catalog paths come from the
// predicate index built over controls + chains; the populated set is
// just the operation paths.
func coverageReport(m mapping, idx predindex.Index) coverage {
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
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].controls != gaps[j].controls {
			return gaps[i].controls > gaps[j].controls
		}
		if gaps[i].chains != gaps[j].chains {
			return gaps[i].chains > gaps[j].chains
		}
		return gaps[i].path < gaps[j].path
	})
	top := gaps
	if len(top) > 5 {
		top = top[:5]
	}
	out := coverage{
		CatalogPaths:   len(catalogPaths),
		Populated:      hits,
		UnpopulatedTop: make([]unpopulated, 0, len(top)),
	}
	if len(catalogPaths) > 0 {
		out.PercentPopulated = float64(hits) / float64(len(catalogPaths)) * 100
	}
	for _, g := range top {
		out.UnpopulatedTop = append(out.UnpopulatedTop, unpopulated{
			Path: g.path, Controls: g.controls, Chains: g.chains,
		})
	}
	return out
}

// overall folds structural errors, schema warnings, and coverage gaps
// into a single status. Structural errors always fail; schema warnings
// and coverage gaps fail only under --strict.
func overall(r report, strict bool) string {
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

func writeText(w io.Writer, r report) error {
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
		return err
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Structural:")
	if len(r.Structural) == 0 {
		fmt.Fprintln(w, "  ok")
	} else {
		for _, f := range r.Structural {
			renderFinding(w, f)
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
			renderFinding(w, f)
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
				return err
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Result: %s\n", r.OverallStatus)
	return nil
}

func renderFinding(w io.Writer, f finding) {
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

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
