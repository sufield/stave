package stave

import staveenv "github.com/sufield/stave/internal/env"

// EnvVar describes one supported STAVE_* environment variable: its name,
// help text, category, currently-resolved value (the env override, or ""
// when unset), and default. It is the flattened form [ListEnvVars]
// returns so callers depend only on pkg/stave.
type EnvVar struct {
	Name         string
	Description  string
	Category     string
	Value        string
	DefaultValue string
}

// ListEnvVars returns every supported STAVE_* environment variable with
// its resolved value. It is the library entry point behind
// `stave env list`.
func ListEnvVars() []EnvVar {
	vars := staveenv.All()
	out := make([]EnvVar, len(vars))
	for i, v := range vars {
		out[i] = EnvVar{
			Name:         v.Name,
			Description:  v.Description,
			Category:     v.Category,
			Value:        v.Value(),
			DefaultValue: v.DefaultValue,
		}
	}
	return out
}
