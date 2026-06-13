package harness

import (
	"cmp"
	"slices"
)

// Compare joins CEL findings against Z3 findings via the supplied
// control-mapping (Stave control ID → Z3 query name) and produces
// one [FindingComparison] per (asset, Z3 query) pair seen on
// either side.
//
// Joining rules:
//
//   - An asset that Z3 emitted a verdict for AND that has at least
//     one CEL finding whose control ID maps to the same query →
//     the comparison joins them. SAT vs FAIL agree; SAT vs PASS
//     classifies as Z3Only; UNSAT vs FAIL classifies as CELOnly;
//     UNSAT vs PASS agree.
//   - A Z3 verdict on an asset that has no CEL finding mapped to
//     the same query → counted as a single check with empty
//     CELControlID (verdict "PASS" by absence).
//   - A CEL finding on an asset with no corresponding Z3 emission
//     for the mapped query → counted as a check with empty
//     Z3QueryName (Z3 verdict "PASS" by absence).
//
// The comparator does not run Z3 or Stave; it is a pure join
// operating on the slices the runner gathered.
func Compare(cel []CELFinding, z3 []Z3Finding, mapping map[string]string, fixtureDir string) []FindingComparison {
	// Build lookup tables.
	celByAssetQuery := indexCELByQuery(cel, mapping)
	z3ByAssetQuery := indexZ3(z3)

	keys := mergeKeys(celByAssetQuery, z3ByAssetQuery)
	slices.SortFunc(keys, func(a, b assetQuery) int {
		if a.asset != b.asset {
			return cmp.Compare(a.asset, b.asset)
		}
		return cmp.Compare(a.query, b.query)
	})

	out := make([]FindingComparison, 0, len(keys))
	for _, k := range keys {
		celSet := celByAssetQuery[k]
		z3Find, hasZ3 := z3ByAssetQuery[k]

		comp := FindingComparison{
			AssetID:       k.asset,
			Z3QueryName:   k.query,
			Investigation: StatusPending,
			FixtureDir:    fixtureDir,
		}

		switch {
		case len(celSet) > 0 && hasZ3:
			comp.CELControlID = anyControl(celSet)
			comp.CELVerdict = "FAIL"
			comp.Z3Verdict = z3Find.Verdict
			comp.Z3Witness = z3Find.Witness
			comp.Z3UnsatCore = z3Find.UnsatCore
			if z3Find.Verdict == "FAIL" {
				comp.Result = AgreeFail
			} else {
				comp.Result = CELOnly
			}
		case len(celSet) > 0:
			// CEL fired but Z3 did not emit anything for the mapped query.
			comp.CELControlID = anyControl(celSet)
			comp.CELVerdict = "FAIL"
			comp.Z3Verdict = "PASS"
			comp.Result = CELOnly
		case hasZ3:
			comp.Z3Verdict = z3Find.Verdict
			comp.Z3Witness = z3Find.Witness
			comp.Z3UnsatCore = z3Find.UnsatCore
			if z3Find.Verdict == "FAIL" {
				comp.CELVerdict = "PASS"
				comp.Result = Z3Only
			} else {
				comp.CELVerdict = "PASS"
				comp.Result = AgreePass
			}
		}
		out = append(out, comp)
	}
	return out
}

// assetQuery is the join key: the comparator considers a CEL
// finding and a Z3 finding to refer to the same check when they
// share both an asset ID and a Z3 query name (the CEL control's
// mapping target).
type assetQuery struct {
	asset string
	query string
}

func indexCELByQuery(findings []CELFinding, mapping map[string]string) map[assetQuery]map[string]struct{} {
	out := map[assetQuery]map[string]struct{}{}
	for _, f := range findings {
		query, mapped := mapping[f.ControlID]
		if !mapped {
			// Control is outside this service's Z3 surface — skip;
			// the CEL evaluator's verdict on it is not part of the
			// Z3-vs-CEL comparison for this run.
			continue
		}
		k := assetQuery{asset: f.AssetID, query: query}
		if out[k] == nil {
			out[k] = map[string]struct{}{}
		}
		out[k][f.ControlID] = struct{}{}
	}
	return out
}

func indexZ3(findings []Z3Finding) map[assetQuery]Z3Finding {
	out := map[assetQuery]Z3Finding{}
	for _, f := range findings {
		out[assetQuery{asset: f.AssetID, query: f.QueryName}] = f
	}
	return out
}

func mergeKeys(a map[assetQuery]map[string]struct{}, b map[assetQuery]Z3Finding) []assetQuery {
	seen := map[assetQuery]struct{}{}
	out := make([]assetQuery, 0, len(a)+len(b))
	for k := range a {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	for k := range b {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func anyControl(set map[string]struct{}) string {
	if len(set) == 0 {
		return ""
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys[0]
}
