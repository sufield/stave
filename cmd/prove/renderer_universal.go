package prove

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

// UniversalRenderer is the format-dispatch interface for universal evaluation.
type UniversalRenderer interface {
	RenderUniversal(w io.Writer, s *stave.UniversalSummary) error
}

// NewUniversalRenderer maps a format string to its UniversalRenderer.
func NewUniversalRenderer(format string) (UniversalRenderer, error) {
	switch format {
	case "json", "":
		return universalJSONRenderer{}, nil
	case "text":
		return universalTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, text)", format)
}

type universalJSONRenderer struct{}

func (universalJSONRenderer) RenderUniversal(w io.Writer, s *stave.UniversalSummary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s) //nolint:wrapcheck
}

type universalTextRenderer struct{}

func (universalTextRenderer) RenderUniversal(w io.Writer, s *stave.UniversalSummary) error {
	fmt.Fprintln(w, "Universal Statement Evaluation")
	fmt.Fprintln(w, "==============================")
	fmt.Fprintln(w)

	for _, r := range s.Results {
		var mark, label string
		switch {
		case r.Error != "":
			mark = "ERR "
			label = r.Error
		case r.Holds:
			mark = "UNSAT"
			label = "holds"
		default:
			mark = "SAT  "
			label = "violated"
		}

		vacuous := ""
		if r.Vacuous && r.Holds {
			vacuous = " (vacuous)"
		}

		fmt.Fprintf(w, "  %-5s  %-4s  %-42s  %s%s\n", mark, r.ID, r.Name, label, vacuous)

		for _, v := range r.Violations {
			fmt.Fprintf(w, "         %s %s (%s: %v)\n",
				strings.Repeat(" ", len(r.ID)), " ",
				v.Predicate, v.Value)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %d/%d hold, %d violated", s.Hold, s.Total, s.Violated)
	if s.Errored > 0 {
		fmt.Fprintf(w, ", %d error", s.Errored)
	}
	fmt.Fprintln(w, ".")
	return nil
}
