package aliases

import (
	"encoding/json"

	"github.com/spf13/cobra"

	predicates "github.com/sufield/stave/internal/builtin/predicate"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	domainpredicate "github.com/sufield/stave/pkg/alpha/domain/predicate"
)

// AliasesOutput is the JSON output of the aliases inspector.
type AliasesOutput struct {
	Aliases            []predicates.AliasInfo `json:"aliases"`
	SupportedOperators []string               `json:"supported_operators"`
	PredicateDemo      PredicateDemo          `json:"predicate_demo"`
}

// PredicateDemo exercises predicate combinators.
type PredicateDemo struct {
	AndResult         bool `json:"and_result"`
	OrResult          bool `json:"or_result"`
	NotResult         bool `json:"not_result"`
	AlwaysTrueResult  bool `json:"always_true_result"`
	AlwaysFalseResult bool `json:"always_false_result"`
}

func run(cmd *cobra.Command, category string) error {
	// Exercise DefaultRegistry and ListAliasInfo.
	registry := predicates.DefaultRegistry()
	aliasInfos := registry.ListAliasInfo(category)

	// Exercise CompositeResolver.
	composite := predicates.NewCompositeResolver(registry)
	_ = composite.ListAliases(category)

	// Exercise Resolve on the composite resolver.
	if len(aliasInfos) > 0 {
		_, _ = composite.Resolve(aliasInfos[0].Name)
	}

	// Exercise domain predicate operators.
	supported := domainpredicate.ListSupported()
	var opStrings []string
	for _, op := range supported {
		opStrings = append(opStrings, string(op))
	}

	// Exercise CEL EvaluateWithParams by compiling and evaluating a resolved alias.
	if len(aliasInfos) > 0 {
		pred, resolveErr := composite.Resolve(aliasInfos[0].Name)
		if resolveErr == nil {
			compiler, celErr := stavecel.NewCompiler()
			if celErr == nil {
				compiled, compileErr := compiler.Compile(pred)
				if compileErr == nil {
					_, _ = stavecel.EvaluateWithParams(compiled, map[string]any{
						"properties": map[string]any{
							"storage": map[string]any{
								"access": map[string]any{
									"public_read": true,
								},
							},
						},
					}, nil, nil)
				}
			}
		}
	}

	// Exercise kernel predicate combinators.
	isPositive := kernel.Predicate[int](func(v int) bool { return v > 0 })
	isEven := kernel.Predicate[int](func(v int) bool { return v%2 == 0 })

	andPred := kernel.And(isPositive, isEven)
	orPred := kernel.Or(isPositive, isEven)
	notPred := kernel.Not(isPositive)
	alwaysTrue := kernel.AlwaysTrue[int]()
	alwaysFalse := kernel.AlwaysFalse[int]()

	output := AliasesOutput{
		Aliases:            aliasInfos,
		SupportedOperators: opStrings,
		PredicateDemo: PredicateDemo{
			AndResult:         andPred(2),
			OrResult:          orPred(-2),
			NotResult:         notPred(1),
			AlwaysTrueResult:  alwaysTrue(0),
			AlwaysFalseResult: alwaysFalse(0),
		},
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
