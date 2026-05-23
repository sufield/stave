package features

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/controls/pack"
	predicates "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/app/coverage"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/contracts/schema"
	"github.com/sufield/stave/internal/controldata"
)

// InScopeFeature is one capability discovered from the live registries
// of this build. Detail carries the count/description derived from real
// data, never a hardcoded value.
type InScopeFeature struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
}

// discoverInScope reads the same registries the evaluation engine uses,
// so the reported capabilities cannot drift from what the binary can
// actually do. Everything here is sourced from embedded, deterministic
// data — no network, no cwd dependence.
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
