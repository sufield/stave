package chainforge

import (
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// UpstreamDep pairs a source identifier with its default fallback and
// diagnostic template. The migration tool and future control authors
// use this to populate implicit_dependencies on chain YAMLs.
type UpstreamDep struct {
	Source     string
	Fallback   policy.DependencyFallback
	Diagnostic string
}

var sensitivityClassifier = UpstreamDep{
	Source:   "observation.sensitivity_classifier",
	Fallback: policy.FallbackFailClosed,
	Diagnostic: "No sensitivity facts emitted for this account. Blast radius " +
		"assessment cannot distinguish safe identities from unclassified ones. " +
		"Finding may be a false negative.",
}

var souffleReachable = UpstreamDep{
	Source:   "reasoning.souffle.reachable_resource",
	Fallback: policy.FallbackCrossValidate,
	Diagnostic: "Datalog reachability engine output not available. Assessment " +
		"uses observation-layer counts only, which may undercount transitive " +
		"role assumptions.",
}

var networkTopology = UpstreamDep{
	Source:   "observation.network_topology",
	Fallback: policy.FallbackFailClosed,
	Diagnostic: "Network topology resolution not available. Routing-dependent " +
		"controls cannot verify reachability between segments.",
}

var ghostResolver = UpstreamDep{
	Source:   "observation.ghost_reference_resolver",
	Fallback: policy.FallbackFailOpen,
	Diagnostic: "Ghost reference resolution depends on snapshot completeness " +
		"for the referenced resource type. If the referenced service was not " +
		"collected, ghost references cannot be detected.",
}

// controlDeps maps individual control IDs to their upstream
// computation dependencies. Controls not in this map evaluate
// snapshot-local fields only and have no implicit dependencies.
var controlDeps = map[kernel.ControlID][]UpstreamDep{
	// sensitivity_classifier
	"CTL.IAM.IDENTITY.BLASTRADIUS.002": {sensitivityClassifier},
	"CTL.IAM.IDENTITY.BLASTRADIUS.004": {sensitivityClassifier},

	// souffle.reachable_resource
	"CTL.IAM.CROSS.ENV.PATH.001":            {souffleReachable},
	"CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001": {souffleReachable},
	"CTL.IAM.IDENTITY.BLASTRADIUS.001":      {souffleReachable},
	"CTL.IAM.IDENTITY.BLASTRADIUS.005":      {souffleReachable},
	"CTL.IAM.VENDOR.OVERPRIVILEGED.001":     {souffleReachable},

	// network_topology
	"CTL.VPC.PEERING.ROUTES.001":       {networkTopology},
	"CTL.EVENTBRIDGE.APIDEST.HTTP.001": {networkTopology},
}

func init() {
	// ghost_reference_resolver: every control whose ID contains ".GHOST."
	// is auto-registered. The explicit map entries above take precedence
	// for controls that also appear there (none currently overlap).
}

// LookupDeps returns the implicit dependencies for a control. Ghost
// controls (ID contains ".GHOST.") automatically get the ghost
// resolver dependency. Returns nil for controls with no upstream deps.
func LookupDeps(id kernel.ControlID) []UpstreamDep {
	if deps, ok := controlDeps[id]; ok {
		return deps
	}
	if strings.Contains(string(id), ".GHOST.") {
		return []UpstreamDep{ghostResolver}
	}
	return nil
}

// ChainDeps computes the union of implicit dependencies for a set of
// member controls, deduplicating by source. Order is deterministic:
// entries appear in the order their source is first seen.
func ChainDeps(controlIDs []kernel.ControlID) []policy.ImplicitDependency {
	seen := map[string]struct{}{}
	var result []policy.ImplicitDependency
	for _, cid := range controlIDs {
		for _, dep := range LookupDeps(cid) {
			if _, ok := seen[dep.Source]; ok {
				continue
			}
			seen[dep.Source] = struct{}{}
			result = append(result, policy.ImplicitDependency{
				Source:     dep.Source,
				Fallback:   dep.Fallback,
				Diagnostic: dep.Diagnostic,
			})
		}
	}
	return result
}
