// Command proofclass classifies controls by proof strength and outputs
// a YAML fragment for docs/metrics.yaml.
//
// Classification:
//
//   - trivial: kind discriminator + ≤1 substantive eq/ne check.
//     Universality is structural — no formal proof needed.
//   - compound: multi-condition predicates, nested logic, or numeric
//     thresholds. Formal verification adds value.
//
// Usage:
//
//	go run ./internal/tools/proofclass
package main

import (
	"fmt"
	"os"
	"strings"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func main() {
	registry := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := registry.All()
	if err != nil {
		fmt.Fprintf(os.Stderr, "proofclass: %v\n", err)
		os.Exit(1)
	}

	var trivial, compound int
	for _, ctl := range controls {
		if isTrivial(ctl) {
			trivial++
		} else {
			compound++
		}
	}

	fmt.Println("proof_class:")
	fmt.Printf("  trivial: %d\n", trivial)
	fmt.Printf("  compound: %d\n", compound)
}

func isTrivial(ctl policy.ControlDefinition) bool {
	p := ctl.UnsafePredicate
	rules := p.All
	if len(rules) == 0 {
		rules = p.Any
	}
	if len(rules) == 0 {
		return true
	}

	substantive := 0
	for _, r := range rules {
		if isKindDiscriminator(r) {
			continue
		}
		if len(r.Any) > 0 || len(r.All) > 0 {
			return false
		}
		substantive++
	}
	return substantive <= 1
}

func isKindDiscriminator(r policy.PredicateRule) bool {
	return strings.HasSuffix(r.Field.String(), ".kind")
}
