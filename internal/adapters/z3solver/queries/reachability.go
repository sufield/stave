//go:build cgo && z3

package queries

import (
	"fmt"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/z3solver/compiler"
)

const reachabilityMaxHops = 5

// QueryReachability answers "Can principal X reach resource Y through
// any chain of role assumptions and policy grants?".
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

	chains := enumerateChains(model, from, reachabilityMaxHops)

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

func enumerateChains(model *compiler.CompiledModel, from string, maxHops int) [][]string {
	chains := [][]string{{from}}
	visited := map[string]struct{}{from: {}}
	frontier := []string{from}

	for hop := 0; hop < maxHops; hop++ {
		var next []string
		for _, current := range frontier {
			for _, e := range model.TrustEdges {
				if e.Assumer != current {
					continue
				}
				if _, ok := visited[e.Assumee]; ok {
					continue
				}
				visited[e.Assumee] = struct{}{}
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

func checkAccessAny(model *compiler.CompiledModel, principal, resource string) (bool, string) {
	for action := range model.Actions {
		r := QueryCompatibility(model, principal, action, resource)
		if r.Result == "satisfiable" {
			return true, action
		}
	}
	return false, ""
}
