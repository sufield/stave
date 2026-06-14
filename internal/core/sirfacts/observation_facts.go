package sirfacts

import (
	"fmt"
	"math"
	"slices"
	"strconv"

	"github.com/sufield/stave/internal/core/sir"
)

// scalarString renders a scalar property leaf as a string suitable
// for the Object of a fact triple. It exists because the observations
// loader uses plain json.Unmarshal (no UseNumber), so every JSON
// number — including integers like 31536000 — lands as a float64.
// fmt's default %v verb renders magnitudes >= 1e6 / < 1e-4 in
// scientific notation ("3.1536e+07"), which breaks reasoning-engine
// queries that string-compare against the literal decimal digits. For
// an integral float64 we emit the plain decimal form ("31536000"); all
// other types fall through to %v.
func scalarString(val any) string {
	switch v := val.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		if math.Trunc(v) == v && !math.IsInf(v, 0) {
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return strconv.FormatFloat(v, 'g', -1, 64)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// ObservationFacts walks the full properties tree of every asset and
// emits one triple per scalar leaf, with the dot-joined property path
// as the predicate and source "observation".
//
// # Why this exists alongside propertyFacts and AutoPropertyFacts
//
// propertyFacts projects a hand-curated has_<leaf> allowlist; the
// curated set is governance, not coverage, so it deliberately omits
// most observation fields. AutoPropertyFacts walks the predicate index
// (only paths some control reads) under a sanitized auto_prop_*
// namespace, gated to --allowlist-mode full.
//
// Neither gives a reasoning engine the RAW observation primitives in
// their original namespace. Without them an engine can only confirm
// Stave's own conclusions (the contributed_by exposure edges) — it
// cannot independently derive a finding from first principles. With
// them, a Datalog/SMT consumer computes, e.g.:
//
//	escalation(U, T) :-
//	  observation(U, "identity.escalation.create_access_key.present", "true"),
//	  observation(U, "identity.escalation.create_access_key.target_user_arn", T),
//	  observation(T, "identity.policies.has_admin_access", "true").
//
// That derivation never touches a contributed_by edge.
//
// # Scope
//
// Scalars only: nested maps are descended; slice and map leaves are
// skipped (closed-world axioms over non-scalar values are ill-defined,
// the same rule lookupScalar and propertyFacts apply). Null leaves and
// empty-string scalars are skipped. Map keys are visited in sorted
// order at every level so the output is deterministic regardless of
// Go's randomized map iteration.
//
// # Namespace
//
// The predicate is the literal dot-joined path (e.g.
// "identity.escalation.create_access_key.present") — not the sanitized
// auto_prop_ form — so JSONL consumers read the property path directly
// and SMT consumers can quote it. This is a distinct namespace from
// the has_* / can_* curated predicates; existing solvers reading those
// see no new assertions on the predicates they know.
//
// # Layering
//
// ObservationFacts is NOT part of ExtractFacts. ExtractFacts feeds both
// `stave export-sir` and applycore's per-finding ContributingFactIDs
// trace; folding raw observation facts in there would silently expand
// every finding's fact-id list and churn the apply goldens. Instead the
// export-sir command appends ObservationFacts unconditionally (both
// allowlist modes), keeping `stave apply` output byte-identical while
// the reasoning-engine export gains the primitives.
func ObservationFacts(assets []sir.AssetFact) []Fact {
	var out []Fact
	for i := range assets {
		a := &assets[i]
		capturedAt := ""
		if a.Lifecycle != nil && !a.Lifecycle.LastSeen.IsZero() {
			capturedAt = a.Lifecycle.LastSeen.UTC().Format("2006-01-02T15:04:05Z")
		}
		out = appendObservationLeaves(out, a.ID, "", a.Properties, capturedAt)
	}
	return out
}

// appendObservationLeaves recurses into a property map, emitting a
// fact for each scalar leaf reachable through nested maps. prefix is
// the dot-joined path accumulated so far ("" at the asset root).
func appendObservationLeaves(out []Fact, assetID, prefix string, node map[string]any, capturedAt string) []Fact {
	keys := make([]string, 0, len(node))
	for k := range node {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		switch val := node[k].(type) {
		case map[string]any:
			out = appendObservationLeaves(out, assetID, path, val, capturedAt)
		case []any, nil:
			// Slices and nulls are skipped: scalars-only, matching
			// lookupScalar and propertyFacts.
			continue
		default:
			obj := scalarString(val)
			if obj == "" {
				continue
			}
			out = append(out, Fact{
				FactID:    factID(assetID, path, obj),
				Subject:   assetID,
				Predicate: path,
				Object:    obj,
				Source:    "observation",
				Evidence:  "assets." + assetID + ".properties." + path,
				Provenance: &Provenance{
					PropertyPath: "properties." + path,
					CapturedAt:   capturedAt,
					Projector:    "observationFacts",
				},
			})
		}
	}
	return out
}
