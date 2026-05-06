// Package sirbridge wires platform-specific adapters to the
// vendor-neutral sir.RoleChainSource / sir.LifecycleSource /
// sir.PermissionAggregator interfaces. It lives in adapters
// rather than app because the bridges import internal/platform
// (the IAM resolver, the engine's lifecycle builder), which
// internal/app is forbidden to do (see
// internal/app/architecture_dependency_test.go).
//
// The bridges are deliberately thin: each one runs an existing
// production pipeline and translates the result into vendor-
// neutral SIR types. No aggregation logic lives here that
// doesn't already live in the production adapter.
package sirbridge

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// AWSRoleChainSource implements sir.RoleChainSource by walking
// every snapshot, running the canonical IAM resolution pipeline
// (iam.ResolveAllPrincipals → iam.ResolveChains), and translating
// the result into vendor-neutral RoleChainFact values.
//
// Construction has no required parameters — the source is
// stateless and the resolver behaviour is fully driven by the
// snapshot it consumes.
type AWSRoleChainSource struct{}

// NewAWSRoleChainSource returns a ready-to-use AWS chain source.
func NewAWSRoleChainSource() *AWSRoleChainSource { return &AWSRoleChainSource{} }

// RoleChains satisfies sir.RoleChainSource. For each snapshot we
// (a) build the resolved-permissions index for every principal,
// (b) walk that index running ResolveChains per principal, and
// (c) merge the resulting per-principal chain lists across
// snapshots. Cross-snapshot merging dedupes by FinalRoleARN +
// hop sequence so a principal observed unchanged across two
// snapshots reports the same chain set once, not twice.
func (s *AWSRoleChainSource) RoleChains(snapshots []asset.Snapshot) (map[asset.ID][]sir.RoleChainFact, error) {
	out := make(map[asset.ID][]sir.RoleChainFact)
	dedupKey := func(c sir.RoleChainFact) string {
		// FinalRoleARN + ordered FromARNs uniquely identifies a
		// chain; no two distinct chains can share both because
		// either the final role differs or the path that reached
		// it does.
		var b strings.Builder
		b.WriteString(c.FinalRoleARN)
		for i := range c.Hops {
			b.WriteByte('|')
			b.WriteString(c.Hops[i].From)
			b.WriteString("->")
			b.WriteString(c.Hops[i].To)
		}
		return b.String()
	}

	for i := range snapshots {
		snap := &snapshots[i]
		resolved, trusts := iam.ResolveAllPrincipals(snap)
		if len(resolved) == 0 {
			continue
		}
		// Iter 3: extract service-principal trusts as a side-channel
		// so the chain walker can recognise execution-role hops
		// (Lambda / ECS / CFN / etc.). The iam.PolicyDocument parser
		// drops Principal blocks; ExtractServiceTrusts probes the
		// raw trust JSON to recover the data without changing the
		// existing iam.Statement shape.
		serviceTrusts := iam.ExtractServiceTrusts(snap)
		for j := range snap.Identities {
			id := &snap.Identities[j]
			chains := iam.ResolveChains(iam.RoleChainInput{
				PrincipalARN:  string(id.ID),
				ResolvedIndex: resolved,
				TrustPolicies: trusts,
				ServiceTrusts: serviceTrusts,
				AccountID:     iam.ExtractAccountIDFromARN(string(id.ID)),
			})
			if len(chains) == 0 {
				continue
			}
			seen := make(map[string]struct{}, len(out[id.ID]))
			for _, existing := range out[id.ID] {
				seen[dedupKey(existing)] = struct{}{}
			}
			for _, ch := range chains {
				fact := translateRoleChain(ch)
				key := dedupKey(fact)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out[id.ID] = append(out[id.ID], fact)
			}
		}
	}
	return out, nil
}

// translateRoleChain maps one iam.RoleChain into the SIR's
// vendor-neutral RoleChainFact. The translation is direct: hops
// preserve their cross-account flag, the final role's privilege
// level is stringified, and the termination reason is rendered
// as a stable lowercase token the solver can branch on.
func translateRoleChain(c iam.RoleChain) sir.RoleChainFact {
	hops := make([]sir.RoleHopFact, len(c.Hops))
	for i := range c.Hops {
		hops[i] = sir.RoleHopFact{
			From:         c.Hops[i].FromARN,
			To:           c.Hops[i].ToARN,
			CrossAccount: c.Hops[i].IsCrossAccount,
			HopType:      hopTypeLabel(c.Hops[i].Type),
		}
	}
	return sir.RoleChainFact{
		Hops:              hops,
		FinalRoleARN:      c.FinalRoleARN,
		TransitiveLevel:   string(c.TransitiveLevel),
		TerminationReason: chainTerminationLabel(c.TerminationReason),
	}
}

// hopTypeLabel translates iam.HopType to the SIR's stable
// wire-format string. Empty / unrecognised input maps to
// "assume_role" because that's the only kind the pre-Iter-2
// walker produced; old hops constructed without a Type field
// kept that meaning.
func hopTypeLabel(t iam.HopType) string {
	switch t {
	case iam.HopTypeTagMutation:
		return "tag_mutation"
	case iam.HopTypeLambdaExec:
		return "lambda_exec"
	case iam.HopTypeEcsExec:
		return "ecs_exec"
	case iam.HopTypeCodebuildExec:
		return "codebuild_exec"
	case iam.HopTypeGlueExec:
		return "glue_exec"
	case iam.HopTypeCfnExec:
		return "cfn_exec"
	case iam.HopTypeAssume, "":
		return "assume_role"
	default:
		return string(t)
	}
}

// chainTerminationLabel maps the iam termination enum to a stable
// lowercase wire token. Centralised here rather than calling
// String on the enum (which doesn't yet exist on the iam type)
// so the SIR's wire vocabulary is locked even if the iam package
// renumbers its constants in the future.
func chainTerminationLabel(r iam.ChainTerminationReason) string {
	switch r {
	case iam.ChainTerminatedNormal:
		return "normal"
	case iam.ChainTerminatedMaxDepth:
		return "max_depth"
	case iam.ChainTerminatedCycle:
		return "cycle"
	case iam.ChainTerminatedNotInSnapshot:
		return "not_in_snapshot"
	default:
		return "unknown"
	}
}
