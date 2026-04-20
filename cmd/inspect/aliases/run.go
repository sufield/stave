package aliases

import (
	"encoding/json"
	"io"

	predicates "github.com/sufield/stave/internal/builtin/predicate"
	domainpredicate "github.com/sufield/stave/internal/core/predicate"
)

// Output is the JSON output of the aliases inspector.
type Output struct {
	Aliases            []predicates.AliasInfo `json:"aliases"`
	SupportedOperators []string               `json:"supported_operators"`
}

// Input is the per-run payload assembled at the RunE boundary.
type Input struct {
	Stdout   io.Writer
	Category string
}

func run(in Input) error {
	registry := predicates.DefaultAliasRegistry()
	aliasInfos := registry.ListAliasInfo(in.Category)

	supported := domainpredicate.ListSupported()
	opStrings := make([]string, len(supported))
	for i, op := range supported {
		opStrings[i] = string(op)
	}

	enc := json.NewEncoder(in.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(Output{
		Aliases:            aliasInfos,
		SupportedOperators: opStrings,
	})
}
