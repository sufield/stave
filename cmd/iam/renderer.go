package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the format-dispatch interface for `stave iam loop`.
type Renderer interface {
	Render(w io.Writer, r *stave.IAMLoopResult) error
}

// NewRenderer maps a format string to its Renderer.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "text", "":
		return textRenderer{}, nil
	case "json":
		return jsonRenderer{}, nil
	}
	return nil, &ui.UserError{
		Err: fmt.Errorf("unknown format %q (valid: text, json)", format),
	}
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, r *stave.IAMLoopResult) error {
	for _, asset := range r.Observation.Assets {
		fmt.Fprintf(w, "Role: %s\n", asset.ID)
		renderProperties(w, asset.Properties, "  ")
	}
	return nil
}

func renderProperties(w io.Writer, props map[string]any, indent string) {
	identity, ok := props["identity"].(map[string]any)
	if !ok {
		fmt.Fprintf(w, "%s(no identity properties)\n", indent)
		return
	}

	if policies, ok := identity["policies"].(map[string]any); ok {
		keys := sortedKeys(policies)
		for _, k := range keys {
			v := policies[k]
			switch val := v.(type) {
			case []any:
				strs := make([]string, 0, len(val))
				for _, item := range val {
					strs = append(strs, fmt.Sprint(item))
				}
				fmt.Fprintf(w, "%s%-38s %s\n", indent, k+":", strings.Join(strs, ", "))
			default:
				fmt.Fprintf(w, "%s%-38s %v\n", indent, k+":", v)
			}
		}
	}

	if trust, ok := identity["trust"].(map[string]any); ok {
		fmt.Fprintf(w, "%strust:\n", indent)
		for k, v := range trust {
			switch val := v.(type) {
			case map[string]any:
				fmt.Fprintf(w, "%s  %s:\n", indent, k)
				for kk, vv := range val {
					fmt.Fprintf(w, "%s    %-34s %v\n", indent, kk+":", vv)
				}
			default:
				fmt.Fprintf(w, "%s  %-36s %v\n", indent, k+":", val)
			}
		}
	}

	if cicd, ok := identity["cicd"].(map[string]any); ok {
		fmt.Fprintf(w, "%scicd:\n", indent)
		for k, v := range cicd {
			fmt.Fprintf(w, "%s  %-36s %v\n", indent, k+":", v)
		}
	}

	if ea, ok := identity["effective_access"].(map[string]any); ok {
		services := sortedKeys(ea)
		fmt.Fprintf(w, "%s%-38s %s\n", indent, "effective_access:", strings.Join(services, ", "))
	}

	if cicdRole, ok := identity["cicd_role"]; ok {
		fmt.Fprintf(w, "%s%-38s %v\n", indent, "cicd_role:", cicdRole)
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type jsonRenderer struct{}

func (jsonRenderer) Render(w io.Writer, r *stave.IAMLoopResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r.Observation)
}
