package stave

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	contractschema "github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predindex"
)

// contractPathRow is the per-path row that ships in both text and JSON
// output for a single asset type.
type contractPathRow struct {
	Path             string `json:"path"`
	ControlsCount    int    `json:"controls_count"`
	ChainsCount      int    `json:"chains_count"`
	MaxSeverity      string `json:"max_severity,omitempty"`
	IsIntentProperty bool   `json:"is_intent_property"`
}

type contractTypeReport struct {
	AssetType        string            `json:"asset_type"`
	HasSchema        bool              `json:"has_schema"`
	SchemaPath       string            `json:"schema_path,omitempty"`
	ControlsCount    int               `json:"controls_count"`
	ChainsCount      int               `json:"chains_count"`
	PropertyPaths    []contractPathRow `json:"property_paths"`
	SteampipeMapping string            `json:"steampipe_mapping,omitempty"`
}

type contractListRow struct {
	AssetType        string `json:"asset_type"`
	HasSchema        bool   `json:"has_schema"`
	ControlsCount    int    `json:"controls_count"`
	ChainsCount      int    `json:"chains_count"`
	SteampipeMapping bool   `json:"steampipe_mapping"`
}

type contractListReport struct {
	Types         []contractListRow `json:"types"`
	TotalTypes    int               `json:"total_types"`
	WithSchema    int               `json:"with_schema"`
	WithSteampipe int               `json:"with_steampipe"`
}

// ContractShowType renders the agent-facing input contract for one asset
// type: the per-asset JSON Schema, the property paths the catalog reads
// (with control/chain counts and severity), and any Steampipe mapping.
// Output is rendered as "json" or "text"/"". An asset type with no
// applicable controls wraps [ErrInvalidInput]. It is the library entry
// point behind `stave contract show --asset-type`.
func ContractShowType(ctx context.Context, assetType, controlsDir, chainsDir, steampipeDir, format string) ([]byte, error) {
	idx, err := loadContractIndex(ctx, controlsDir, chainsDir)
	if err != nil {
		return nil, err
	}
	return renderContractType(assetType, idx, steampipeDir, format)
}

// ContractList renders the catalog of every asset type with at least one
// applicable control, showing schema and Steampipe-mapping presence and
// control/chain counts, as "json" or "text"/"". It is the library entry
// point behind `stave contract show --list`.
func ContractList(ctx context.Context, controlsDir, chainsDir, steampipeDir, format string) ([]byte, error) {
	idx, err := loadContractIndex(ctx, controlsDir, chainsDir)
	if err != nil {
		return nil, err
	}
	return renderContractList(idx, steampipeDir, format)
}

// loadContractIndex loads the control + chain catalogs and builds the
// path -> controls/chains reverse index. Loader failures stay plain
// (exit 4); a missing chains dir is non-fatal (chain counts become zero).
func loadContractIndex(ctx context.Context, controlsDir, chainsDir string) (predindex.Index, error) {
	controls, err := loadControlsFromDir(ctx, controlsDir)
	if err != nil {
		return predindex.Index{}, err
	}
	chains, err := loadChainsOptional(chainsDir)
	if err != nil {
		return predindex.Index{}, err
	}
	return predindex.Build(controls, chains), nil
}

func renderContractType(assetType string, idx predindex.Index, steampipeDir, format string) ([]byte, error) {
	at := kernel.AssetType(assetType)
	paths := idx.TypeToPaths[at]
	if len(paths) == 0 {
		return nil, fmt.Errorf("no controls declare applicable_asset_types: [%s]: %w", assetType, ErrInvalidInput)
	}

	rows := make([]contractPathRow, 0, len(paths))
	chainSet := map[kernel.ChainID]struct{}{}
	controlSet := map[kernel.ControlID]struct{}{}
	for _, p := range paths {
		ctls := idx.PathToControls[p]
		chs := idx.PathToChains[p]
		for _, c := range ctls {
			controlSet[c] = struct{}{}
		}
		for _, ch := range chs {
			chainSet[ch] = struct{}{}
		}
		rows = append(rows, contractPathRow{
			Path:             p,
			ControlsCount:    len(ctls),
			ChainsCount:      len(chs),
			MaxSeverity:      idx.PathMaxSeverity[p].String(),
			IsIntentProperty: isIntentProperty(p),
		})
	}
	slices.SortFunc(rows, func(a, b contractPathRow) int {
		return cmp.Or(
			cmp.Compare(b.ChainsCount, a.ChainsCount),
			cmp.Compare(b.ControlsCount, a.ControlsCount),
			cmp.Compare(a.Path, b.Path),
		)
	})

	report := contractTypeReport{
		AssetType:     assetType,
		PropertyPaths: rows,
		ControlsCount: len(controlSet),
		ChainsCount:   len(chainSet),
	}
	if _, err := contractschema.AssetTypeSchema(assetType); err == nil {
		report.HasSchema = true
		report.SchemaPath = fmt.Sprintf("schemas/observation/v1/asset-types/%s.schema.json", assetType)
	}
	if mapping := findSteampipeMapping(steampipeDir, assetType); mapping != "" {
		report.SteampipeMapping = mapping
	}

	var buf bytes.Buffer
	if format == "json" {
		if err := writeContractJSON(&buf, report); err != nil {
			return nil, fmt.Errorf("render contract: %w", err)
		}
	} else {
		if err := writeContractTypeText(&buf, report); err != nil {
			return nil, fmt.Errorf("render contract: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func renderContractList(idx predindex.Index, steampipeDir, format string) ([]byte, error) {
	types := make([]string, 0, len(idx.TypeToPaths))
	for t := range idx.TypeToPaths {
		types = append(types, string(t))
	}
	slices.Sort(types)

	rows := make([]contractListRow, 0, len(types))
	withSchema := 0
	withSteampipe := 0
	for _, t := range types {
		row := contractListRow{AssetType: t}
		if _, err := contractschema.AssetTypeSchema(t); err == nil {
			row.HasSchema = true
			withSchema++
		}
		paths := idx.TypeToPaths[kernel.AssetType(t)]
		ctlSet := map[kernel.ControlID]struct{}{}
		chSet := map[kernel.ChainID]struct{}{}
		for _, p := range paths {
			for _, c := range idx.PathToControls[p] {
				ctlSet[c] = struct{}{}
			}
			for _, c := range idx.PathToChains[p] {
				chSet[c] = struct{}{}
			}
		}
		row.ControlsCount = len(ctlSet)
		row.ChainsCount = len(chSet)
		if findSteampipeMapping(steampipeDir, t) != "" {
			row.SteampipeMapping = true
			withSteampipe++
		}
		rows = append(rows, row)
	}
	report := contractListReport{
		Types:         rows,
		TotalTypes:    len(rows),
		WithSchema:    withSchema,
		WithSteampipe: withSteampipe,
	}

	var buf bytes.Buffer
	if format == "json" {
		if err := writeContractJSON(&buf, report); err != nil {
			return nil, fmt.Errorf("render contract list: %w", err)
		}
	} else {
		if err := writeContractListText(&buf, report); err != nil {
			return nil, fmt.Errorf("render contract list: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// findSteampipeMapping returns the (workspace-relative) path of the
// matching contracts/steampipe/<type>.yaml when it exists, or the empty
// string when no mapping is present.
func findSteampipeMapping(dir, assetType string) string {
	if dir == "" {
		return ""
	}
	candidate := filepath.Join(dir, assetType+".yaml")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

// isIntentProperty returns true when the path looks like operator-declared
// intent (tags, role-type labels, environment markers). Matches the
// heuristic the gaps command uses so output stays consistent.
func isIntentProperty(path string) bool {
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, ".tags."):
		return true
	case strings.HasSuffix(low, ".data_classification"):
		return true
	case strings.HasSuffix(low, ".environment"):
		return true
	case strings.HasSuffix(low, ".role_type"):
		return true
	}
	return false
}

func writeContractJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func writeContractTypeText(w io.Writer, r contractTypeReport) error {
	fmt.Fprintf(w, "Contract: %s\n", r.AssetType)
	if r.HasSchema {
		fmt.Fprintf(w, "Schema:   %s\n", r.SchemaPath)
	} else {
		fmt.Fprintf(w, "Schema:   (none — no per-asset schema registered)\n")
	}
	fmt.Fprintf(w, "Controls: %d | Chains: %d\n\n", r.ControlsCount, r.ChainsCount)

	if len(r.PropertyPaths) == 0 {
		fmt.Fprintln(w, "(no property paths declared)")
		return nil
	}

	fmt.Fprintln(w, "Property paths (catalog reads these — sorted by chain unlock, then control unlock):")
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  PATH\tCONTROLS\tCHAINS\tSEVERITY\tNOTE")
	fmt.Fprintln(tw, "  ────\t────────\t──────\t────────\t────")
	for _, p := range r.PropertyPaths {
		note := ""
		if p.IsIntentProperty {
			note = "intent"
		}
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%s\t%s\n",
			strings.TrimPrefix(p.Path, "properties."),
			p.ControlsCount, p.ChainsCount, p.MaxSeverity, note)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush contract table: %w", err)
	}

	if r.SteampipeMapping != "" {
		fmt.Fprintf(w, "\nSteampipe mapping: %s\n", r.SteampipeMapping)
	} else {
		fmt.Fprintln(w, "\nSteampipe mapping: (none — author one at contracts/steampipe/"+r.AssetType+".yaml)")
	}
	return nil
}

func writeContractListText(w io.Writer, r contractListReport) error {
	fmt.Fprintf(w, "Asset types with controls: %d (schema: %d, steampipe mapping: %d)\n\n",
		r.TotalTypes, r.WithSchema, r.WithSteampipe)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  TYPE\tSCHEMA\tCONTROLS\tCHAINS\tMAPPING")
	fmt.Fprintln(tw, "  ────\t──────\t────────\t──────\t───────")
	for _, t := range r.Types {
		schema := "-"
		if t.HasSchema {
			schema = "yes"
		}
		mapping := "-"
		if t.SteampipeMapping {
			mapping = "steampipe"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%s\n",
			t.AssetType, schema, t.ControlsCount, t.ChainsCount, mapping)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush list table: %w", err)
	}
	return nil
}
