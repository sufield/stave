package validate

import (
	"fmt"

	"github.com/sufield/stave/internal/cli/ui"
)

// kindAliases maps CLI --kind input to a canonical content kind string. The
// canonical strings ("control", "observation", "finding") are what the
// validate facade expects; resolving aliases stays command-side because it
// uses the cli/ui token helpers.
var kindAliases = map[string]string{
	"control":     "control",
	"controls":    "control",
	"observation": "observation",
	"obs":         "observation",
	"snapshot":    "observation",
	"snapshots":   "observation",
	"finding":     "finding",
	"findings":    "finding",
}

// normalizeKind converts a CLI --kind alias into its canonical kind string.
func normalizeKind(raw string) (string, error) {
	if k, ok := kindAliases[ui.NormalizeToken(raw)]; ok {
		return k, nil
	}
	return "", fmt.Errorf("normalize schema kind: %w", ui.EnumError("--kind", raw, []string{"control", "observation", "finding"}))
}
