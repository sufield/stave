package architecture_test

// Catalog structural invariants discovered by bounded model checking
// (formal/catalog.als, formal/catalog-checks.als) and confirmed against
// the real catalog. Each test encodes one Alloy finding; see
// docs-internal/alloy-findings.md for the full analysis.
//
// These are stubs — they load the catalog and check the invariant but
// do NOT fix violations. When a stub fails, the output names the
// offending controls/chains/fields so the catalog author can triage.

import (
	"testing"

	builtin "github.com/sufield/stave/internal/adapters/controls/builtin"
	yamladapter "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/collectorcontract"
	"github.com/sufield/stave/internal/controldata"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func loadCatalog(t *testing.T) ([]policy.ControlDefinition, []policy.ChainDefinition) {
	t.Helper()

	store := builtin.NewControlStore(controldata.FS, "embedded")
	controls, err := store.All()
	if err != nil {
		t.Fatalf("load controls: %v", err)
	}

	chains, err := yamladapter.LoadChainsFS(controldata.FS, "embedded/chains", nil)
	if err != nil {
		t.Fatalf("load chains: %v", err)
	}

	return controls, chains
}

// F1: Every property path a control reads should exist in the collector contract.
func TestNoGhostPropertyPaths(t *testing.T) {
	controls, _ := loadCatalog(t)

	contract, err := collectorcontract.Load()
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}
	contracted := contract.FieldIndex()

	var ghosts int
	for _, ctl := range controls {
		ctl.UnsafePredicate.Walk(func(r policy.PredicateRule) {
			field := r.Field.String()
			if field == "" {
				return
			}
			if _, ok := contracted[field]; !ok {
				ghosts++
				if ghosts <= 20 {
					t.Errorf("ghost: control %s reads uncontracted field %q", ctl.ID, field)
				}
			}
		})
	}
	if ghosts > 20 {
		t.Errorf("... and %d more ghost property paths", ghosts-20)
	}
	if ghosts > 0 {
		t.Errorf("total: %d property paths not in collector contract", ghosts)
	}
}

// F2: Every contracted field should be consumed by at least one control.
func TestNoOrphanContractFields(t *testing.T) {
	contract, err := collectorcontract.Load()
	if err != nil {
		t.Fatalf("load contract: %v", err)
	}

	var orphans int
	for _, entry := range contract.Entries {
		if len(entry.Consumers) == 0 {
			orphans++
			if orphans <= 20 {
				t.Errorf("orphan contract field %q has no consumers", entry.Field)
			}
		}
	}
	if orphans > 20 {
		t.Errorf("... and %d more orphan contract fields", orphans-20)
	}
	if orphans > 0 {
		t.Errorf("total: %d contract fields with zero consumers", orphans)
	}
}

// F3: Chain compound_severity >= max(member control severities).
func TestCompoundSeverityEscalates(t *testing.T) {
	controls, chains := loadCatalog(t)

	ctlIndex := make(map[string]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlIndex[string(controls[i].ID)] = &controls[i]
	}

	var violations int
	for _, ch := range chains {
		var maxSev policy.Severity
		for _, cid := range ch.ControlIDs {
			if ctl, ok := ctlIndex[string(cid)]; ok {
				if ctl.Severity > maxSev {
					maxSev = ctl.Severity
				}
			}
		}
		if ch.CompoundSeverity < maxSev {
			violations++
			if violations <= 10 {
				t.Errorf("chain %s: compound_severity=%v < max_member=%v",
					ch.ID, ch.CompoundSeverity, maxSev)
			}
		}
	}
	if violations > 10 {
		t.Errorf("... and %d more compound severity violations", violations-10)
	}
	if violations > 0 {
		t.Errorf("total: %d chains with compound_severity < max member severity", violations)
	}
}

// F5: Asset-scoped chains must have at least one asset type common to all controls.
func TestNoDeadAssetScopedChains(t *testing.T) {
	controls, chains := loadCatalog(t)

	ctlIndex := make(map[string]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlIndex[string(controls[i].ID)] = &controls[i]
	}

	var dead int
	for _, ch := range chains {
		if ch.Scope != "" && ch.Scope != policy.ScopeAsset {
			continue
		}

		if len(ch.ControlIDs) == 0 {
			continue
		}

		// Compute intersection of applicable asset types.
		var intersection map[string]bool
		for i, cid := range ch.ControlIDs {
			ctl, ok := ctlIndex[string(cid)]
			if !ok {
				continue
			}
			types := make(map[string]bool, len(ctl.ApplicableAssetTypes))
			for _, at := range ctl.ApplicableAssetTypes {
				types[string(at)] = true
			}
			if i == 0 || intersection == nil {
				intersection = types
			} else {
				for k := range intersection {
					if !types[k] {
						delete(intersection, k)
					}
				}
			}
		}

		if len(intersection) == 0 {
			dead++
			if dead <= 10 {
				t.Errorf("dead chain %s: scope=%q, no common asset type across %d controls",
					ch.ID, ch.Scope, len(ch.ControlIDs))
			}
		}
	}
	if dead > 10 {
		t.Errorf("... and %d more dead asset-scoped chains", dead-10)
	}
	if dead > 0 {
		t.Errorf("total: %d asset-scoped chains with empty asset type intersection", dead)
	}
}

// F6: Every chain precondition should appear in some chain's postconditions.
func TestPreconditionsSatisfiable(t *testing.T) {
	_, chains := loadCatalog(t)

	preconditions := make(map[string]bool)
	postconditions := make(map[string]bool)

	for _, ch := range chains {
		for _, cap := range ch.Preconditions {
			preconditions[cap] = true
		}
		for _, cap := range ch.Postconditions {
			postconditions[cap] = true
		}
	}

	var unsatisfied int
	for cap := range preconditions {
		if !postconditions[cap] {
			unsatisfied++
			t.Errorf("unsatisfied precondition %q: required but no chain produces it", cap)
		}
	}
	if unsatisfied > 0 {
		t.Errorf("total: %d preconditions not produced by any chain postcondition", unsatisfied)
	}
}

// F7: Every control should be referenced by at least one chain.
func TestNoOrphanControls(t *testing.T) {
	controls, chains := loadCatalog(t)

	referenced := make(map[string]bool)
	for _, ch := range chains {
		for _, cid := range ch.ControlIDs {
			referenced[string(cid)] = true
		}
	}

	var orphans int
	bySev := make(map[policy.Severity]int)
	for _, ctl := range controls {
		if !referenced[string(ctl.ID)] {
			orphans++
			bySev[ctl.Severity]++
			if orphans <= 10 {
				t.Errorf("orphan control %s (severity=%v): not in any chain", ctl.ID, ctl.Severity)
			}
		}
	}
	if orphans > 10 {
		t.Errorf("... and %d more orphan controls", orphans-10)
	}
	if orphans > 0 {
		t.Errorf("total: %d controls not referenced by any chain (critical=%d, high=%d, medium=%d, low=%d, info=%d)",
			orphans,
			bySev[policy.SeverityCritical],
			bySev[policy.SeverityHigh],
			bySev[policy.SeverityMedium],
			bySev[policy.SeverityLow],
			bySev[policy.SeverityInfo])
	}
}
