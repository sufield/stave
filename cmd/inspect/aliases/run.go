package aliases

import (
	"encoding/json"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// Output is the JSON output of the aliases inspector.
type Output struct {
	Aliases            []stave.AliasInfo `json:"aliases"`
	SupportedOperators []string          `json:"supported_operators"`
}

// Input is the per-run payload assembled at the RunE boundary.
type Input struct {
	Stdout   io.Writer
	Category string
}

func run(in Input) error {
	enc := json.NewEncoder(in.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(Output{
		Aliases:            stave.ListPredicateAliases(in.Category),
		SupportedOperators: stave.SupportedOperators(),
	})
}
