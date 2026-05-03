package queries

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/experiments/z3-solver/compiler"
)

// reachabilityMaxHops bounds the assume-role chain length the
// reachability query expands. AWS does not bound chain length but
// real chains in production rarely exceed three hops; the bounded
// model stays decidable and the bound is surfaced in the proof
// certificate as part of ModelCoverage.NotModeled.
const reachabilityMaxHops = 5

// QueryReachability answers "Can principal X reach resource Y
// through any chain of role assumptions and policy grants?". The
// implementation walks the trust-edge graph from the loader / the
// compiler's TrustEdges slice for up to reachabilityMaxHops hops,
// then asks the IAM evaluator whether the final hop's principal
// is granted access to the target resource.
//
// SAT means an attack path exists; the witness names the chain.
// UNSAT means no path within the modeled depth — sound under
// the experiment's "closed universe + bounded depth" assumption,
// which the proof certificate spells out so consumers do not
// over-trust the verdict.
func QueryReachability(model *compiler.CompiledModel, from, to string) *QueryResult {
	start := time.Now()

	r := &QueryResult{
		QueryName: "reachability",
		ModelCoverage: ModelCoverage{
			Modeled: []string{
				"identity_policy", "resource_policy", "kms_key_policy",
				"trust_policy", "assume_role_chain",
			},
			NotModeled: []string{
				"scp", "permissions_boundary", "session_policy",
				"vpc_endpoint_policy",
				fmt.Sprintf("assume_role_chain_depth>%d", reachabilityMaxHops),
			},
		},
	}

	if _, ok := model.Resources[to]; !ok {
		r.Result = "unmodeled"
		r.Interpretation = fmt.Sprintf("resource %q not present in the snapshot's resource universe", to)
		r.SolveTimeMs = time.Since(start).Milliseconds()
		return r
	}

	// Enumerate the assumable identity chain, including direct.
	chains := enumerateChains(model, from, reachabilityMaxHops)

	// For each terminal principal, check whether it is granted
	// access to the resource via any modeled action. The
	// experiment treats reachability as "exists an action where
	// the IAM evaluator returns ALLOW".
	for _, chain := range chains {
		terminal := chain[len(chain)-1]
		if granted, action := checkAccessAny(model, terminal, to); granted {
			r.Result = "satisfiable"
			r.Interpretation = fmt.Sprintf(
				"reachable: %s → %s, terminal grant: %s",
				strings.Join(chain, " → assumes → "), to, action)
			r.Witness = map[string]string{
				"chain":     strings.Join(chain, " → "),
				"terminal":  terminal,
				"action":    action,
				"resource":  to,
				"hop_count": fmt.Sprintf("%d", len(chain)-1),
			}
			r.SolveTimeMs = time.Since(start).Milliseconds()
			return r
		}
	}

	r.Result = "unsatisfiable"
	r.Interpretation = fmt.Sprintf(
		"no path from %s to %s within modeled depth %d",
		from, to, reachabilityMaxHops)
	r.SolveTimeMs = time.Since(start).Milliseconds()
	return r
}

// enumerateChains produces every principal chain starting at from
// of length 1..maxHops. The chain begins with `from` itself
// (depth 1) so a direct grant to `from` is reachable without
// requiring an assume hop.
func enumerateChains(model *compiler.CompiledModel, from string, maxHops int) [][]string {
	chains := [][]string{{from}}
	visited := map[string]bool{from: true}
	frontier := []string{from}

	for hop := 0; hop < maxHops; hop++ {
		next := []string{}
		for _, current := range frontier {
			for _, e := range model.TrustEdges {
				if e.Assumer != current {
					continue
				}
				if visited[e.Assumee] {
					continue
				}
				visited[e.Assumee] = true
				// Build the chain reaching this assumee.
				for _, base := range chains {
					if base[len(base)-1] != current {
						continue
					}
					extension := append([]string{}, base...)
					extension = append(extension, e.Assumee)
					chains = append(chains, extension)
				}
				next = append(next, e.Assumee)
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	return chains
}

// checkAccessAny iterates the model's action universe and asks
// the compatibility predicate for each (principal, action,
// resource) triple. Returns the first action that grants access.
//
// For the reachability query this is the right shape: we want to
// know "is there ANY action this terminal can perform on the
// resource", not a specific action. The early-exit on the first
// grant keeps the query latency bounded by the size of the action
// universe, which is in practice <100 for a single snapshot.
func checkAccessAny(model *compiler.CompiledModel, principal, resource string) (bool, string) {
	for action := range model.Actions {
		r := QueryCompatibility(model, principal, action, resource)
		if r.Result == "satisfiable" {
			return true, action
		}
	}
	return false, ""
}
