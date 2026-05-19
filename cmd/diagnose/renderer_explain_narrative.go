package diagnose

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/narrative"
)

// ExplainNarrativeRenderer is the polymorphic format-dispatch
// interface for `stave diagnose explain`. Three formats: json,
// markdown, and the default narrative (text). Carries the depth
// flag on the text-shaped renderers because writeNarrativePlaybooks
// and writeMarkdownPlaybooks both take it as a parameter and the
// playbook slice doesn't carry it.
//
// JSONRenderer also varies per call: when there's a single playbook
// it emits the bare object (matching the pre-migration shape);
// otherwise it emits an array. That special case is preserved
// inside the renderer's Render method rather than at the call site.
type ExplainNarrativeRenderer interface {
	Render(w io.Writer, playbooks []narrative.Playbook) error
}

// ExplainNarrativeJSONRenderer emits indented JSON. Single-playbook
// runs emit the bare object; multi-playbook runs emit an array.
type ExplainNarrativeJSONRenderer struct{}

// Render implements ExplainNarrativeRenderer.
func (ExplainNarrativeJSONRenderer) Render(w io.Writer, playbooks []narrative.Playbook) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if len(playbooks) == 1 {
		return enc.Encode(playbooks[0])
	}
	return enc.Encode(playbooks)
}

// ExplainNarrativeMarkdownRenderer writes a markdown-formatted
// playbook. Carries Depth because writeMarkdownPlaybooks needs it.
type ExplainNarrativeMarkdownRenderer struct {
	Depth string
}

// Render implements ExplainNarrativeRenderer.
func (r ExplainNarrativeMarkdownRenderer) Render(w io.Writer, playbooks []narrative.Playbook) error {
	writeMarkdownPlaybooks(w, playbooks, r.Depth)
	return nil
}

// ExplainNarrativeTextRenderer writes the default human-readable
// narrative form. Carries Depth.
type ExplainNarrativeTextRenderer struct {
	Depth string
}

// Render implements ExplainNarrativeRenderer.
func (r ExplainNarrativeTextRenderer) Render(w io.Writer, playbooks []narrative.Playbook) error {
	writeNarrativePlaybooks(w, playbooks, r.Depth)
	return nil
}

// NewExplainNarrativeRenderer maps a format string to its concrete
// renderer. Returns an error for unknown formats; the previous
// default branch silently rendered as narrative.
func NewExplainNarrativeRenderer(format, depth string) (ExplainNarrativeRenderer, error) {
	switch format {
	case "json":
		return ExplainNarrativeJSONRenderer{}, nil
	case "markdown":
		return ExplainNarrativeMarkdownRenderer{Depth: depth}, nil
	case "narrative", "text", "":
		return ExplainNarrativeTextRenderer{Depth: depth}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: narrative | json | markdown)", format)
}
