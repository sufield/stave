package cliapi

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/core/sirfacts"
	"github.com/sufield/stave/pkg/stave"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// ExportSIRConfig parameterizes [ExportSIR]. Format is "json"/"" (default),
// "jsonl", or "smt2"; AllowlistMode is "curated" or "full"; Now stamps the
// SIR for deterministic output.
type ExportSIRConfig struct {
	ControlsDir     string
	ObservationsDir string
	Format          string
	Now             time.Time
	Validate        bool
	AllowlistMode   string
	ClosedWorld     bool
	StripCatalog    bool
}

// ExportSIR materializes the Stave Intermediate Representation (SIR) for
// the configured controls + observations (routing through [Apply], the
// same load+evaluate+SIR-build path cmd/apply uses) and renders it in the
// requested format. It returns the rendered SIR bytes and, when Validate
// is set, the projection-coverage report to write to stderr. An unknown
// format wraps [stave.ErrInvalidInput] (exit 2); load/build failures stay
// plain (exit 4). It is the library entry point behind `stave export-sir`.
func ExportSIR(ctx context.Context, cfg ExportSIRConfig) (output []byte, validationOutput []byte, err error) {
	// Validate the format up front so a bad value fails fast — before the
	// expensive load + evaluation.
	switch cfg.Format {
	case "", "json", "jsonl", "smt2":
	default:
		return nil, nil, fmt.Errorf("--format must be one of json | jsonl | smt2 (got %q): %w", cfg.Format, stave.ErrInvalidInput)
	}

	res, err := Apply(ctx, stave.Config{
		ControlsDir:  cfg.ControlsDir,
		SnapshotsDir: cfg.ObservationsDir,
		Now:          cfg.Now,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("evaluate: %w", err)
	}
	if res.IsIncomplete() {
		return nil, nil, errors.New("evaluate: cliapi.Apply returned an incomplete result")
	}
	if res.SIRDocument == nil {
		return nil, nil, errors.New("evaluate: SIR build failed inside cliapi.Apply; no document to project")
	}
	doc := res.SIRDocument

	// Extract facts when the format needs them or --validate asks. The JSON
	// path serialises the nested document directly and skips fact extraction
	// unless --validate is also set.
	var facts []sirfacts.Fact
	if cfg.Format != "json" || cfg.Validate {
		facts = sirfacts.ExtractFacts(doc)
		facts = append(facts, sirfacts.ObservationFacts(doc.Assets)...)
		if cfg.AllowlistMode == "full" {
			facts = append(facts, sirfacts.AutoPropertyFacts(doc.Assets, res.Controls)...)
		}
		sirfacts.AnnotateFreshness(facts, cfg.Now)
	}

	if cfg.Validate {
		warnings := ValidateSIRCompleteness(res.ComplianceReport.Findings, facts, res.Controls)
		validationOutput = renderSIRValidation(warnings)
	}

	if cfg.StripCatalog && (cfg.Format == "jsonl" || cfg.Format == "smt2") {
		facts = sirfacts.FilterOutCatalog(facts)
	}

	output, err = renderSIR(doc, facts, cfg.ClosedWorld, cfg.Format)
	if err != nil {
		return nil, nil, err
	}
	return output, validationOutput, nil
}

// renderSIR renders the SIR as the nested JSON document, a JSONL triple
// stream, or SMT-LIB v2 facts. Split out so it is unit-testable.
func renderSIR(doc *sir.Document, facts []sirfacts.Fact, closedWorld bool, format string) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "", "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return nil, fmt.Errorf("encode SIR: %w", err)
		}
	case "jsonl":
		if err := sirfacts.SerializeJSONL(facts, &buf); err != nil {
			return nil, fmt.Errorf("encode jsonl: %w", err)
		}
	case "smt2":
		if err := sirfacts.SerializeSMT2(facts, &buf, sirfacts.SMT2Options{ClosedWorld: closedWorld}); err != nil {
			return nil, fmt.Errorf("encode smt2: %w", err)
		}
	default:
		return nil, fmt.Errorf("--format must be one of json | jsonl | smt2 (got %q): %w", format, stave.ErrInvalidInput)
	}
	return buf.Bytes(), nil
}

// ValidationWarning is one (control, asset, property-path) tuple that
// fired in CEL but lacks a covering SIR fact for the asset.
type ValidationWarning struct {
	ControlID string `json:"control_id"`
	AssetID   string `json:"asset_id"`
	CELPath   string `json:"cel_path"`
	Message   string `json:"message"`
}

// ValidateSIRCompleteness compares the property paths each fired control
// evaluates (from its UnsafePredicate AST) against the paths the SIR fact
// projection emits (from each fact's provenance). Returns one
// ValidationWarning per (finding, uncovered path) pair. Coverage matching
// is bidirectional substring on the "properties."-stripped path.
func ValidateSIRCompleteness(
	findings []evaluation.Finding,
	facts []sirfacts.Fact,
	controls []policy.ControlDefinition,
) []ValidationWarning {
	if len(findings) == 0 || len(facts) == 0 {
		return nil
	}

	factPathsByAsset := make(map[string]map[string]bool)
	for _, f := range facts {
		if f.Provenance == nil || f.Provenance.PropertyPath == "" {
			continue
		}
		set := factPathsByAsset[f.Subject]
		if set == nil {
			set = make(map[string]bool)
			factPathsByAsset[f.Subject] = set
		}
		set[f.Provenance.PropertyPath] = true
	}

	pathsByControl := make(map[kernel.ControlID][]string)
	for i := range controls {
		c := &controls[i]
		paths := extractPredicateFieldPaths(c.UnsafePredicate)
		if len(paths) > 0 {
			pathsByControl[c.ID] = paths
		}
	}

	var warnings []ValidationWarning
	for i := range findings {
		f := &findings[i]
		celPaths, ok := pathsByControl[f.ControlID]
		if !ok || len(celPaths) == 0 {
			continue
		}
		assetPaths := factPathsByAsset[string(f.AssetID)]
		for _, celPath := range celPaths {
			if pathCovered(celPath, assetPaths) {
				continue
			}
			warnings = append(warnings, ValidationWarning{
				ControlID: string(f.ControlID),
				AssetID:   string(f.AssetID),
				CELPath:   celPath,
				Message: fmt.Sprintf(
					"Control %s evaluates %s but no SIR fact covers this property path. "+
						"SMT queries cannot distinguish vulnerable from remediated for this control.",
					f.ControlID, celPath),
			})
		}
	}

	slices.SortFunc(warnings, func(a, b ValidationWarning) int {
		return cmp.Or(
			cmp.Compare(a.ControlID, b.ControlID),
			cmp.Compare(a.AssetID, b.AssetID),
			cmp.Compare(a.CELPath, b.CELPath),
		)
	})

	return warnings
}

// extractPredicateFieldPaths walks an UnsafePredicate AST and returns every
// `Field` path stripped of the leading "properties." prefix. Empty Field
// values (parent any/all nodes) are skipped. Results are deduped + sorted.
func extractPredicateFieldPaths(p policy.UnsafePredicate) []string {
	seen := make(map[string]struct{})
	p.Walk(func(rule policy.PredicateRule) {
		if rule.Field.IsZero() {
			return
		}
		path := strings.TrimPrefix(rule.Field.String(), "properties.")
		if path == "" {
			return
		}
		seen[path] = struct{}{}
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// pathCovered reports whether any fact path covers the control predicate
// path. Coverage is substring-based in either direction.
func pathCovered(celPath string, assetPaths map[string]bool) bool {
	for factPath := range assetPaths {
		if factPath == celPath {
			return true
		}
		if strings.Contains(factPath, celPath) {
			return true
		}
		if strings.Contains(celPath, factPath) {
			return true
		}
	}
	return false
}

// renderSIRValidation produces the --validate stderr report: a "no gaps"
// banner when warnings is empty, or the grep-friendly gap block otherwise.
func renderSIRValidation(warnings []ValidationWarning) []byte {
	var buf bytes.Buffer
	if len(warnings) == 0 {
		fmt.Fprintln(&buf, "SIR validation: all CEL-evaluated properties are projected. No gaps.")
		return buf.Bytes()
	}
	fmt.Fprintf(&buf, "\n%d SIR projection gap(s) detected:\n\n", len(warnings))
	for i := range warnings {
		buf.WriteString("  WARNING: ")
		buf.WriteString(warnings[i].Message)
		buf.WriteByte('\n')
		buf.WriteString("           Asset: ")
		buf.WriteString(warnings[i].AssetID)
		buf.WriteString("\n\n")
	}
	fmt.Fprintf(&buf, "These controls fire in CEL but the properties they evaluate\n")
	fmt.Fprintf(&buf, "are not projected into the SIR. Add projector entries in\n")
	fmt.Fprintf(&buf, "cmd/exportsir/facts.go to close these gaps.\n\n")
	return buf.Bytes()
}
