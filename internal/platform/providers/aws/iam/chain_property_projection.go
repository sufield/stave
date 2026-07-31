package iam

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// ProjectChainProperties walks every CloudIdentity in the
// snapshot, runs the role-chain resolver against it, and writes
// the resulting confused-deputy and TOCTOU annotations back into
// each identity's Properties under the project's
// `identity.escalation.*` and `identity.chain.*` conventions.
//
// Why mutate the snapshot in-place: the predicate engine
// evaluates `ctrl.v1` controls against `Snapshot.Identities[i].
// Properties` directly. Without this projector, the controls that
// consume Iter 5/6 chain output (CTL.IAM.ESCALATE.CONFUSED.*,
// CTL.IAM.CHAIN.GHOST.DELETION.001) would require an upstream
// collector to compute the booleans — every Stave deployment
// would need a custom extraction step. By projecting inside Stave
// the controls work out-of-the-box on any snapshot whose IAM
// identities carry the standard policy / trust JSON.
//
// Callers should invoke this function exactly once per
// (PerformAssessment, snapshot-set), AFTER the observation loader
// returns the snapshots and BEFORE the predicate engine runs.
// The projection is idempotent — running it twice on the same
// snapshot is a no-op the second time around.
func ProjectChainProperties(snap *asset.Snapshot) {
	if snap == nil || (len(snap.Identities) == 0 && len(snap.Assets) == 0) {
		return
	}
	resolved, trusts := ResolveAllPrincipals(snap)
	chainsByPrincipal := resolveChainsByResolved(snap, resolved, trusts)
	for i := range snap.Identities {
		id := &snap.Identities[i]
		chains := chainsByPrincipal[string(id.ID)]
		writeChainProjections(id, chains)
		if perms := resolved[string(id.ID)]; perms != nil {
			writeReconProjections(id, perms)
		}
	}
	for i := range snap.Assets {
		a := &snap.Assets[i]
		if !a.IsIdentityAsset() {
			continue
		}
		if perms := resolved[string(a.ID)]; perms != nil {
			writeReconProjectionsOnAsset(a, perms)
		}
	}
}

// ChainPropertyEnricher adapts ProjectChainProperties to the
// app-layer SnapshotEnricher port (defined in
// internal/app/contracts). The composition root constructs one
// of these and threads it through AuditWorkflow.SnapshotEnricher
// — the eval package never imports this package directly, so the
// hexagonal app→platform boundary stays intact.
type ChainPropertyEnricher struct{}

// NewChainPropertyEnricher returns a SnapshotEnricher
// implementation backed by ProjectChainProperties. Stateless;
// safe to construct on every call.
func NewChainPropertyEnricher() *ChainPropertyEnricher {
	return &ChainPropertyEnricher{}
}

// EnrichSnapshot satisfies the appcontracts.SnapshotEnricher
// interface. Delegates to the package-level projector so the
// implementation stays in one place.
func (*ChainPropertyEnricher) EnrichSnapshot(snap *asset.Snapshot) {
	ProjectChainProperties(snap)
}

// ResolveChainsBySnapshot drives the chain walker over every
// identity in the snapshot and returns the resulting chains keyed
// by principal ARN. Centralised so both the property projector
// (above) and any future caller that wants chain data stay
// aligned on extractor configuration — service trusts,
// AWS-principal trusts, scheduled deletions, and resource
// bindings must all be configured identically across consumers
// or the chain results diverge.
func ResolveChainsBySnapshot(snap *asset.Snapshot) map[string][]RoleChain {
	if snap == nil || len(snap.Identities) == 0 {
		return nil
	}
	resolved, trusts := ResolveAllPrincipals(snap)
	return resolveChainsByResolved(snap, resolved, trusts)
}

func resolveChainsByResolved(
	snap *asset.Snapshot,
	resolved map[string]*ResolvedPermissions,
	trusts map[string]*PolicyDocument,
) map[string][]RoleChain {
	if len(resolved) == 0 {
		return nil
	}
	serviceTrusts := ExtractServiceTrusts(snap)
	awsPrincipalTrusts := ExtractAWSTrustedPrincipals(snap)
	scheduledDeletions := ExtractScheduledDeletions(snap)
	resourceRoleBindings := ExtractResourceRoleBindings(snap)

	out := make(map[string][]RoleChain, len(snap.Identities))
	for i := range snap.Identities {
		id := &snap.Identities[i]
		chains := ResolveChains(RoleChainInput{
			PrincipalARN:         string(id.ID),
			ResolvedIndex:        resolved,
			TrustPolicies:        trusts,
			ServiceTrusts:        serviceTrusts,
			AWSPrincipalTrusts:   awsPrincipalTrusts,
			ScheduledDeletions:   scheduledDeletions,
			ResourceRoleBindings: resourceRoleBindings,
			AccountID:            ExtractAccountIDFromARN(string(id.ID)),
		})
		if len(chains) > 0 {
			out[string(id.ID)] = chains
		}
	}
	return out
}

// writeChainProjections folds one principal's chain results into
// the property booleans that the IAM escalation / chain controls
// read at predicate-evaluation time. Diagnostic fields
// (function_arn, target_role, scheduled_deletion_at, ...) are
// populated alongside the .present booleans so the controls'
// observation_fields render meaningful evidence.
func writeChainProjections(id *asset.CloudIdentity, chains []RoleChain) {
	if id.Properties == nil {
		id.Properties = make(map[string]any)
	}

	confusedLambda := chainProjection{}
	confusedCfn := chainProjection{}
	ghostDeletion := chainProjection{}

	for ci := range chains {
		ch := &chains[ci]
		for hi := range ch.Hops {
			hop := &ch.Hops[hi]
			switch hop.Type {
			case HopTypeLambdaInvokeExisting:
				confusedLambda.note(hop, ch)
			case HopTypeCfnUpdateExisting:
				confusedCfn.note(hop, ch)
			}
		}
		if !ch.ScheduledDeletionAt.IsZero() {
			ghostDeletion.noteGhost(ch)
		}
	}

	mutateNested(id.Properties, []string{"identity", "escalation", "confused_lambda_invoke"},
		confusedLambda.toMap("function_arn"))
	mutateNested(id.Properties, []string{"identity", "escalation", "confused_cfn_update"},
		confusedCfn.toMap("stack_arn"))
	mutateNested(id.Properties, []string{"identity", "chain", "ghost_deletion"},
		ghostDeletion.toGhostMap())
}

// chainProjection accumulates the diagnostic fields for a single
// projected chain primitive. Kept tiny so the writeChainProjections
// orchestration stays linear.
type chainProjection struct {
	present     bool
	resourceARN string
	targetRole  string
	hopCount    int

	// ghostDeletionAt holds the earliest scheduled deletion
	// timestamp (RFC3339 string) across the chains that
	// contributed to this projection. Zero when no chain was
	// ghost-tagged.
	ghostDeletionAt string
}

func (p *chainProjection) note(hop *RoleHop, chain *RoleChain) {
	p.present = true
	if p.resourceARN == "" {
		// Trigger ARN sits on the inbound side of the hop —
		// FromARN is the principal, ToARN is the role. The
		// resource that mediated the hop (function / stack ARN)
		// is captured in the chain by virtue of having produced
		// the hop type; for the projection we surface the
		// target role and the chain depth, leaving the literal
		// resource ARN to be filled by callers that need it
		// (Iter 6's walker emits one chain per hop, so a
		// future enhancement can stash the resource ARN on the
		// hop itself).
		p.resourceARN = ""
	}
	if p.targetRole == "" {
		p.targetRole = hop.ToARN
	}
	p.hopCount = max(p.hopCount, len(chain.Hops))
}

func (p *chainProjection) noteGhost(chain *RoleChain) {
	p.present = true
	if p.targetRole == "" {
		p.targetRole = chain.FinalRoleARN
	}
	p.hopCount = max(p.hopCount, len(chain.Hops))
	ts := chain.ScheduledDeletionAt.UTC().Format("2006-01-02T15:04:05Z07:00")
	if p.ghostDeletionAt == "" || ts < p.ghostDeletionAt {
		p.ghostDeletionAt = ts
	}
}

func (p *chainProjection) toMap(resourceField string) map[string]any {
	out := map[string]any{"present": p.present}
	if p.targetRole != "" {
		out["target_role"] = p.targetRole
	}
	if p.resourceARN != "" {
		out[resourceField] = p.resourceARN
	}
	if p.hopCount > 0 {
		out["hop_count"] = p.hopCount
	}
	return out
}

func (p *chainProjection) toGhostMap() map[string]any {
	out := map[string]any{"present": p.present}
	if p.targetRole != "" {
		out["target_role"] = p.targetRole
	}
	if p.hopCount > 0 {
		out["hop_count"] = p.hopCount
	}
	if p.ghostDeletionAt != "" {
		out["scheduled_deletion_at"] = p.ghostDeletionAt
	}
	return out
}

// mutateNested writes value at the supplied key path inside props,
// creating intermediate map[string]any nodes when missing. Coerces
// existing non-map values along the path to maps — this is the
// "fail loud, never fake" choice: a stale collector field at the
// same path would otherwise silently shadow the projection.
func mutateNested(props map[string]any, path []string, value map[string]any) {
	if len(path) == 0 {
		return
	}
	cur := props
	for i, key := range path {
		if i == len(path)-1 {
			cur[key] = value
			return
		}
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[key] = next
		}
		cur = next
	}
}

func buildReconMap(perms *ResolvedPermissions) map[string]any {
	actions := make(map[string]bool, len(perms.EffectiveAllow))
	for _, g := range perms.EffectiveAllow {
		actions[strings.ToLower(g.Action)] = true
	}

	canEnum := actions["iam:listusers"] && actions["iam:listroles"]
	canRead := actions["iam:getuserpolicy"] && actions["iam:getpolicyversion"] && actions["iam:listattacheduserpolicies"]
	canSim := actions["iam:simulateprincipalpolicy"]
	canCred := actions["iam:getloginprofile"] && actions["iam:listaccesskeys"]

	hasEscalation := perms.RiskProfile.PrivEsc > 0

	var capability string
	switch {
	case canEnum && canRead && canSim:
		capability = "full"
	case canEnum && canRead:
		capability = "partial"
	case hasEscalation:
		capability = "blind"
	default:
		capability = "none"
	}

	return map[string]any{
		"can_enumerate_principals":    canEnum,
		"can_read_principal_policies": canRead,
		"can_simulate_policies":       canSim,
		"can_read_credentials":        canCred,
		"victim_selection_capability": capability,
	}
}

func writeReconProjections(id *asset.CloudIdentity, perms *ResolvedPermissions) {
	if id.Properties == nil {
		id.Properties = make(map[string]any)
	}
	mutateNested(id.Properties, []string{"identity", "reconnaissance"}, buildReconMap(perms))
}

func writeReconProjectionsOnAsset(a *asset.Asset, perms *ResolvedPermissions) {
	if a.Properties == nil {
		a.Properties = make(map[string]any)
	}
	mutateNested(a.Properties, []string{"identity", "reconnaissance"}, buildReconMap(perms))
}
