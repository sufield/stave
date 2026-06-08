package stave

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"

	scopemanifest "github.com/sufield/stave/features"
	"github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/controls/pack"
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/app/coverage"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/controldata"
)

// InScopeFeature is one capability discovered from the live registries of
// this build. Detail carries the count/description derived from real data.
type InScopeFeature struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// featuresPayload is the rendered document: live IN SCOPE discovery plus
// the versioned OUT OF SCOPE manifest.
type featuresPayload struct {
	InScope    []InScopeFeature                `json:"in_scope"`
	OutOfScope []scopemanifest.OutOfScopeEntry `json:"out_of_scope"`
}

// RenderFeatures reports Stave's capability scope: IN SCOPE discovered live
// from this build's registries (control catalog, packs, frameworks,
// schemas, ATT&CK tactics) and OUT OF SCOPE from the versioned
// features/scope.yaml manifest, rendered as "text"/"auto"/"", "wide", or
// "json". An unknown format wraps [ErrInvalidInput] (exit 2); a manifest
// load failure stays plain (exit 4). It is the library entry point behind
// `stave features`.
func RenderFeatures(format string) ([]byte, error) {
	switch format {
	case "text", "auto", "", "wide", "json":
	default:
		return nil, fmt.Errorf("--format must be auto | text | wide | json (got %q): %w", format, ErrInvalidInput)
	}

	outOfScope, err := scopemanifest.OutOfScope()
	if err != nil {
		return nil, fmt.Errorf("load scope manifest: %w", err)
	}
	doc := featuresPayload{InScope: discoverInScope(), OutOfScope: outOfScope}

	var buf bytes.Buffer
	switch format {
	case "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return nil, fmt.Errorf("render features: %w", err)
		}
	case "wide":
		if err := renderFeaturesWide(&buf, doc); err != nil {
			return nil, fmt.Errorf("render features: %w", err)
		}
	default: // text, auto, ""
		if err := renderFeaturesText(&buf, doc); err != nil {
			return nil, fmt.Errorf("render features: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func renderFeaturesText(w io.Writer, p featuresPayload) error {
	if _, err := fmt.Fprint(w, "\nIN SCOPE (discovered from this build)\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "─────────────────────────────────────"); err != nil {
		return err
	}
	for _, f := range p.InScope {
		if _, err := fmt.Fprintf(w, "  ✓ %-22s %s\n", f.Label, f.Detail); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprint(w, "\nOUT OF SCOPE (by design — see features/scope.yaml)\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "──────────────────────────────────────────────────"); err != nil {
		return err
	}
	for _, e := range p.OutOfScope {
		detail := e.Reason
		if len(e.Alternatives) > 0 {
			detail = fmt.Sprintf("%s: %s", e.Reason, strings.Join(e.Alternatives, ", "))
		}
		if _, err := fmt.Fprintf(w, "  → %-22s %s\n", e.Label, detail); err != nil {
			return err
		}
	}
	return nil
}

// renderFeaturesWide is the columnar variant of the text view.
func renderFeaturesWide(w io.Writer, p featuresPayload) error {
	if _, err := fmt.Fprint(w, "\nIN SCOPE (discovered from this build)\n"); err != nil {
		return err
	}
	in := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(in, "  CAPABILITY\tDETAIL"); err != nil {
		return err
	}
	for _, f := range p.InScope {
		if _, err := fmt.Fprintf(in, "  ✓ %s\t%s\n", f.Label, f.Detail); err != nil {
			return err
		}
	}
	if err := in.Flush(); err != nil {
		return fmt.Errorf("flush in-scope table: %w", err)
	}

	if _, err := fmt.Fprint(w, "\nOUT OF SCOPE (by design — see features/scope.yaml)\n"); err != nil {
		return err
	}
	out := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(out, "  CAPABILITY\tREASON\tALTERNATIVES"); err != nil {
		return err
	}
	for _, e := range p.OutOfScope {
		if _, err := fmt.Fprintf(out, "  → %s\t%s\t%s\n", e.Label, e.Reason, strings.Join(e.Alternatives, ", ")); err != nil {
			return err
		}
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("flush out-of-scope table: %w", err)
	}
	return nil
}

// discoverInScope reads the same registries the evaluation engine uses, so
// the reported capabilities cannot drift from what the binary can do.
// Everything is sourced from embedded, deterministic data.
func discoverInScope() []InScopeFeature {
	return []InScopeFeature{
		{Label: "Control Catalog", Detail: catalogDetail()},
		{Label: "Observation Schemas", Detail: schemaDetail()},
		{Label: "Predicate Evaluation", Detail: predicateDetail()},
		{Label: "Output Formats", Detail: "text, json, sarif (apply evaluation output)"},
		{Label: "Compliance Frameworks", Detail: frameworkDetail()},
		{Label: "Risk Reasoning", Detail: riskDetail()},
		{Label: "Snapshot Diff", Detail: "asset/property change comparison between two snapshots"},
		{Label: "Air-Gapped Operation", Detail: "no network during evaluation (--require-offline asserts it)"},
	}
}

func catalogDetail() string {
	store := builtin.NewControlStore(controldata.FS, "embedded",
		builtin.WithAliasResolver(predicates.ResolverFunc()))
	controls, err := store.All()
	if err != nil {
		return fmt.Sprintf("control catalog unavailable: %v", err)
	}
	packs := "?"
	if reg, perr := pack.NewEmbeddedRegistry(); perr == nil {
		packs = strconv.Itoa(len(reg.PackNames()))
	}
	return fmt.Sprintf("%d controls across %s packs", len(controls), packs)
}

func schemaDetail() string {
	versions := schema.SupportedVersions(schema.KindObservation)
	assetTypes := schema.AssetTypesWithSchema()
	return fmt.Sprintf("obs.v0.1 (%s), %d asset-type schemas",
		strings.Join(versions, ", "), len(assetTypes))
}

func predicateDetail() string {
	if _, err := cel.NewPredicateEval(); err != nil {
		return fmt.Sprintf("CEL engine unavailable: %v", err)
	}
	return "CEL engine (deterministic, non-Turing-complete)"
}

func frameworkDetail() string {
	fw := compliance.SupportedFrameworks()
	sample := make([]string, 0, 3)
	for i, f := range fw {
		if i >= 3 {
			break
		}
		sample = append(sample, string(f))
	}
	suffix := ""
	if len(fw) > len(sample) {
		suffix = "…"
	}
	return fmt.Sprintf("%d frameworks (%s%s)", len(fw), strings.Join(sample, ", "), suffix)
}

func riskDetail() string {
	return fmt.Sprintf("%d ATT&CK tactics, chain escalation scoring", len(coverage.AllTactics))
}
