package aliases

import (
	"encoding/json"

	"github.com/spf13/cobra"

	predicates "github.com/sufield/stave/internal/builtin/predicate"
	domainpredicate "github.com/sufield/stave/internal/core/predicate"
)

// AliasesOutput is the JSON output of the aliases inspector.
type AliasesOutput struct {
	Aliases            []predicates.AliasInfo `json:"aliases"`
	SupportedOperators []string               `json:"supported_operators"`
}

func run(cmd *cobra.Command, category string) error {
	registry := predicates.DefaultRegistry()
	aliasInfos := registry.ListAliasInfo(category)

	supported := domainpredicate.ListSupported()
	opStrings := make([]string, len(supported))
	for i, op := range supported {
		opStrings[i] = string(op)
	}

	output := AliasesOutput{
		Aliases:            aliasInfos,
		SupportedOperators: opStrings,
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
