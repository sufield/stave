package discover

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/pkg/stave/pack"
)

// Renderer is the format-dispatch interface for `stave discover`.
type Renderer interface {
	Render(w io.Writer, m manifest) error
}

// NewRenderer maps a format string to its Renderer (unknown -> exit 2 at the factory).
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "text", "":
		return textRenderer{}, nil
	case "json":
		return jsonRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}

type jsonRenderer struct{}

func (jsonRenderer) Render(w io.Writer, m manifest) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return fmt.Errorf("encode manifest JSON: %w", err)
	}
	return nil
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, m manifest) error {
	fmt.Fprintf(w, "Services requested: %s\n", strings.Join(m.Services, ", "))
	if m.HasUnmatchedServices() {
		fmt.Fprintf(w, "  (no controls/packs cover: %s)\n", strings.Join(m.ServicesUnmatched, ", "))
	}
	fmt.Fprintf(w, "Packs covering them: %s\n", joinOrNone(m.Packs))
	fmt.Fprintf(w, "Controls that will evaluate: %d\n", m.ControlCount)

	writeRequirements(w, &m.Requirements)

	fmt.Fprintf(w, "\nNext: 1) collect the calls above with your own tool (AWS CLI, Steampipe, …) → raw snapshots\n")
	fmt.Fprintf(w, "      2) convert the snapshots into obs.v0.1 observations with your extractor (NOT Stave)\n")
	fmt.Fprintf(w, "      3) run `stave apply -o <observations>`.\n")
	fmt.Fprintf(w, "      Stave never collects data or touches AWS — it reads the observations you produce.\n")
	return nil
}

func writeRequirements(w io.Writer, req *pack.Requirements) {
	fmt.Fprintf(w, "\nCollect these (read-only) AWS API calls:\n")
	if !req.HasAPICalls() {
		fmt.Fprintf(w, "  (none — no covering pack declares API requirements)\n")
	}
	for _, sc := range req.AWSAPICalls {
		fmt.Fprintf(w, "  %s:\n", sc.Service)
		for _, c := range sc.Calls {
			fmt.Fprintf(w, "    %s\n", c)
		}
		if sc.Notes != "" {
			fmt.Fprintf(w, "    # %s\n", sc.Notes)
		}
	}

	if req.HasObservationSignals() {
		fmt.Fprintf(w, "\nRequired observation signals:\n")
		for _, s := range req.ObservationSignals {
			fmt.Fprintf(w, "  %s\n", s)
		}
	}

	if mp := strings.TrimSpace(req.MinimumPermissions); mp != "" {
		fmt.Fprintf(w, "\nMinimum collector permissions:\n")
		for line := range strings.SplitSeq(mp, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ", ")
}
