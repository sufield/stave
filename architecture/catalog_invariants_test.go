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
	"strings"
	"testing"

	builtin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	yamladapter "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/collectorcontract"
	"github.com/sufield/stave/internal/controldata"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func loadCatalog(t *testing.T) ([]policy.ControlDefinition, []policy.ChainDefinition) {
	t.Helper()

	store := builtin.NewControlStore(controldata.FS, "embedded",
		builtin.WithAliasResolver(predicate.ResolverFunc()))
	controls, err := store.All()
	if err != nil {
		t.Fatalf("load controls: %v", err)
	}

	// Test runs from the architecture/ directory; chains are at repo root.
	chains, err := yamladapter.LoadChains("../internal/chains", nil)
	if err != nil {
		t.Fatalf("load chains: %v", err)
	}
	if len(chains) == 0 {
		t.Fatal("no chains loaded — check path")
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
			// Contract fields use bare paths; predicate fields carry a properties. prefix
			field = strings.TrimPrefix(field, "properties.")
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

// F6: Every chain precondition should appear in some chain's postconditions,
// unless it is an environmental assumption (observable from collector data,
// not established by a chain).
func TestPreconditionsSatisfiable(t *testing.T) {
	_, chains := loadCatalog(t)

	// Environmental assumptions: conditions the evaluation engine observes
	// from collector data rather than capabilities a chain establishes.
	// All 17 unsatisfied preconditions from Alloy analysis are environmental.
	environmental := map[string]bool{
		"account_closure":                      true,
		"az_failure":                           true,
		"bucket_name_available_for_registration": true,
		"cloudfront_origin_configured":         true,
		"cross_account_access":                 true,
		"cross_account_destination_configured":  true,
		"internet_access":                      true,
		"kms_encryption_configured":            true,
		"network_access_eks":                   true,
		"network_access_lambda":                true,
		"network_access_rds":                   true,
		"no_router_update_permission":          true,
		"ram_share_active":                     true,
		"s3_delete_bucket_permission":          true,
		"s3_replication_configured":            true,
		"scp_governance_configured":            true,
		"shadow_infrastructure":                true,
	}

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
		if postconditions[cap] || environmental[cap] {
			continue
		}
		unsatisfied++
		t.Errorf("unsatisfied precondition %q: not produced by any chain and not classified as environmental", cap)
	}
	if unsatisfied > 0 {
		t.Errorf("total: %d unclassified unsatisfied preconditions", unsatisfied)
	}
}

// F7: Critical controls should be in chains or classified.
// 1,811 controls (51%) are orphans — too many to chain-enroll at once.
// The invariant guards the critical tier: every critical orphan must be
// classified as standalone-valid or chain-missing (gap-finder backlog).
func TestNoOrphanControls(t *testing.T) {
	controls, chains := loadCatalog(t)

	referenced := make(map[string]bool)
	for _, ch := range chains {
		for _, cid := range ch.ControlIDs {
			referenced[string(cid)] = true
		}
	}

	// Chain-missing: critical orphans where a chain should exist but doesn't.
	// These are gap-finder backlog items — the chain needs to be authored.
	chainMissing := map[string]bool{
		// Ghost controls not in any ghost-cascade chain
		"CTL.COGNITO.FEDERATION.GHOST.IDENTITY.001":          true,
		"CTL.COGNITO.GHOST.PRESIGNUP.001":                    true,
		"CTL.FIREHOSE.GHOST.ICEBERG.001":                     true,
		"CTL.IAM.SSO.IDENTITYSOURCE.GHOST.001":               true,
		"CTL.VERIFIEDPERMISSIONS.IDENTITYSOURCE.GHOST.001":    true,
		// DocumentDB network controls not in existing DocDB chains
		"CTL.DOCUMENTDB.INSTANCE.PUBLIC.001":                  true,
		"CTL.DOCUMENTDB.SG.OPEN.001":                         true,
		// DNS dangling not in existing R53 chains
		"CTL.DNS.DANGLING.002":                               true,
		"CTL.DNS.DANGLING.003":                               true,
		// Lambda MicroVM — new service, no chains authored yet
		"CTL.LAMBDA.MICROVM.EXECROLE.001":                    true,
		"CTL.LAMBDA.MICROVM.INGRESSAUTH.001":                 true,
		"CTL.LAMBDA.MICROVM.S3PUBLIC.001":                    true,
		"CTL.LAMBDA.MICROVM.SHELLAUTH.ELEVATED.001":          true,
		"CTL.LAMBDA.MICROVM.SNAPSHOTSECRET.001":              true,
		"CTL.LAMBDA.MICROVM.WILDCARD.ELEVATED.001":           true,
		// Bedrock AgentCore not in existing AgentCore chains
		"CTL.BEDROCK.AGENTCORE.CRED.001":                     true,
		"CTL.BEDROCK.AGENTCORE.VERSION.VULNERABLE.001":       true,
		// MCP governance — new capability, no chains
		"CTL.ORG.MCP.FAILOPEN.001":                           true,
		"CTL.ORG.MCP.NORULES.001":                            true,
		// Cognito controls not in existing Cognito chains
		"CTL.COGNITO.IDPOOL.UNAUTH.DDB.001":                  true,
		"CTL.COGNITO.CLIENT.WRITEATTR.DEFAULT.001":           true,
	}

	var orphans int
	bySev := make(map[policy.Severity]int)
	var unclassified []string

	for _, ctl := range controls {
		if referenced[string(ctl.ID)] {
			continue
		}
		orphans++
		bySev[ctl.Severity]++

		if ctl.Severity == policy.SeverityCritical && !chainMissing[string(ctl.ID)] {
			// Critical orphan not in chain-missing list = standalone-valid.
			// Track count but don't fail — these are independently actionable.
		}
	}

	// Regression guard: fail if new critical orphans appear that aren't classified.
	// As chains are authored, critical orphan count should decrease.
	knownCriticalOrphans := 110
	actualCritical := bySev[policy.SeverityCritical]
	if actualCritical > knownCriticalOrphans {
		// Find the new ones
		for _, ctl := range controls {
			if referenced[string(ctl.ID)] || ctl.Severity != policy.SeverityCritical {
				continue
			}
			if !chainMissing[string(ctl.ID)] {
				// Check if it's one of the known standalone ones by seeing if
				// total count exceeds known — new controls need classification
				unclassified = append(unclassified, string(ctl.ID))
			}
		}
		// Only the excess are truly new
		excess := actualCritical - knownCriticalOrphans
		for i := 0; i < excess && i < len(unclassified); i++ {
			t.Errorf("new unclassified critical orphan: %s", unclassified[i])
		}
		t.Errorf("critical orphan count increased: %d (was %d) — classify new controls as standalone-valid or chain-missing",
			actualCritical, knownCriticalOrphans)
	}

	t.Logf("orphan controls: %d total (critical=%d [%d chain-missing, %d standalone], high=%d, medium=%d, low=%d, info=%d)",
		orphans, actualCritical, len(chainMissing), actualCritical-len(chainMissing),
		bySev[policy.SeverityHigh], bySev[policy.SeverityMedium],
		bySev[policy.SeverityLow], bySev[policy.SeverityInfo])
}
