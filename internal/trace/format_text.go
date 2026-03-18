package trace

import (
	"fmt"
	"io"
	"slices"
)

// TextWriter renders trace results as indented human-readable text.
type TextWriter struct {
	w      io.Writer
	indent int
	err    error
}

// WriteText renders a Result as indented human-readable text.
func WriteText(w io.Writer, tr *Result) error {
	tw := &TextWriter{w: w}
	tw.render(tr)
	return tw.err
}

func (tw *TextWriter) printf(format string, a ...any) {
	if tw.err != nil {
		return
	}
	for i := 0; i < tw.indent; i++ {
		_, tw.err = io.WriteString(tw.w, "  ")
		if tw.err != nil {
			return
		}
	}
	_, tw.err = fmt.Fprintf(tw.w, format, a...)
}

func (tw *TextWriter) render(tr *Result) {
	tw.printf("Tracing %s against asset %s\n", string(tr.ControlID), tr.AssetID.String())
	tw.printf("\nAsset Properties:\n")
	tw.renderProperties(tr.Properties, "properties")
	tw.printf("\n")
	tw.renderGroup(tr.Root)
	tw.printf("\n")
	if tr.FinalResult {
		tw.printf("Final Result: PREDICATE MATCHED (asset is unsafe per this control)\n")
		return
	}
	tw.printf("Final Result: PREDICATE DID NOT MATCH (asset is safe per this control)\n")
}

func (tw *TextWriter) renderProperties(props map[string]any, prefix string) {
	lines := make([]string, 0, len(props))
	tw.flatten(props, prefix, &lines)
	slices.Sort(lines)
	tw.indent++
	for _, line := range lines {
		tw.printf("%s\n", line)
	}
	tw.indent--
}

func (tw *TextWriter) renderGroup(g *GroupNode) {
	if g == nil {
		tw.printf("Predicate: (empty)\n")
		return
	}
	tw.printf("Predicate Logic: %s\n", g.Logic)
	tw.indent++
	for i, child := range g.Children {
		tw.renderNode(child)
		if g.ShortCircuitIndex >= 0 && i == g.ShortCircuitIndex {
			if i < len(g.Children)-1 {
				tw.printf("... (short-circuited)\n")
			}
			break
		}
	}
	tw.printf("Conclusion: %s\n", g.Reason)
	tw.indent--
}

func (tw *TextWriter) renderNode(node Node) {
	switch n := node.(type) {
	case *GroupNode:
		tw.printf("[nested %s block]\n", n.Logic)
		tw.renderGroup(n)
	case *ClauseNode:
		tw.renderClause(n)
	case *FieldRefNode:
		tw.renderFieldRef(n)
	case *AnyMatchNode:
		tw.renderAnyMatch(n)
	}
}

func (tw *TextWriter) renderClause(c *ClauseNode) {
	tw.printf("[%d] field: %s  op: %s  value: %s\n",
		c.Index+1, c.Field, c.Op, formatValue(c.Value))
	if !c.ValueFromParam.IsZero() {
		tw.printf("    (param: %s)\n", c.ValueFromParam)
	}
	tw.printf("    Result: %s\n", c.Explain())
}

func (tw *TextWriter) renderFieldRef(f *FieldRefNode) {
	tw.printf("[%d] field: %s  op: %s  compare_to: %s\n",
		f.Index+1, f.Field, f.Op, f.OtherField)
	tw.printf("    Result: %s\n", f.Explain())
}

func (tw *TextWriter) renderAnyMatch(a *AnyMatchNode) {
	tw.printf("[%d] field: %s  op: any_match\n", a.Index+1, a.Field)
	if !a.FieldExists {
		tw.printf("    field absent → FAIL\n")
		return
	}
	tw.printf("    Evaluating %d identities\n", a.IdentityCount)
	if a.Result && a.NestedTrace != nil {
		if a.MatchedIndex >= 0 {
			tw.printf("    Matched identity[%d] %q:\n", a.MatchedIndex, a.MatchedID)
		} else {
			tw.printf("    Matched identity %q:\n", a.MatchedID)
		}
		tw.indent += 2
		tw.renderGroup(a.NestedTrace)
		tw.indent -= 2
		return
	}
	tw.printf("    No identity matched criteria → FAIL\n")
}

// flatten recursively builds a list of "key: value" strings for the property map.
func (tw *TextWriter) flatten(props map[string]any, prefix string, lines *[]string) {
	for k, v := range props {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		if nested, ok := v.(map[string]any); ok {
			tw.flatten(nested, fullKey, lines)
		} else {
			*lines = append(*lines, fmt.Sprintf("%s: %s", fullKey, formatValue(v)))
		}
	}
}
