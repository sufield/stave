package trace

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// TextWriter renders trace results as indented human-readable text.
type TextWriter struct {
	w      io.Writer
	indent int
	err    error
}

func (tw *TextWriter) printf(format string, a ...any) {
	if tw.err != nil {
		return
	}
	_, tw.err = fmt.Fprintf(tw.w, strings.Repeat("  ", tw.indent)+format, a...)
}

// WriteText renders a TraceResult as indented human-readable text.
func WriteText(w io.Writer, tr *TraceResult) error {
	tw := &TextWriter{w: w}
	tw.render(tr)
	return tw.err
}

func (tw *TextWriter) render(tr *TraceResult) {
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
	flattenProperties(props, prefix, &lines)
	sort.Strings(lines)
	tw.indent++
	defer func() { tw.indent-- }()
	for _, line := range lines {
		tw.printf("%s\n", line)
	}
}

func (tw *TextWriter) renderGroup(g *GroupNode) {
	tw.printf("Predicate: %s\n", g.Logic)
	tw.indent++
	defer func() { tw.indent-- }()
	for i, child := range g.Children {
		tw.renderNode(child)
		if g.ShortCircuitIndex >= 0 && i == g.ShortCircuitIndex {
			if i < len(g.Children)-1 {
				tw.printf("... (short-circuited)\n")
			}
			break
		}
	}
	tw.printf("%s\n", g.Reason)
}

func (tw *TextWriter) renderNode(node Node) {
	switch n := node.(type) {
	case *GroupNode:
		tw.printf("[nested %s]\n", n.Logic)
		tw.indent++
		tw.renderGroup(n)
		tw.indent--
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
	if c.ValueFromParam != "" {
		tw.printf("    (value_from_param: %s)\n", c.ValueFromParam)
	}
	tw.printf("    Resolved: %s\n", clauseExplanation(c))
}

func (tw *TextWriter) renderFieldRef(f *FieldRefNode) {
	tw.printf("[%d] field: %s  op: %s  other_field: %s\n",
		f.Index+1, f.Field, f.Op, f.OtherField)
	tw.printf("    Resolved: %s\n", fieldRefExplanation(f))
}

func (tw *TextWriter) renderAnyMatch(a *AnyMatchNode) {
	tw.printf("[%d] field: %s  op: any_match\n", a.Index+1, a.Field)
	if !a.FieldExists {
		tw.printf("    field absent → FAIL\n")
		return
	}
	tw.printf("    Iterating %d identities\n", a.IdentityCount)
	if a.Result && a.NestedTrace != nil {
		if a.MatchedIndex != nil {
			tw.printf("    Matched identity[%d] %q:\n", *a.MatchedIndex, a.MatchedID)
		} else {
			tw.printf("    Matched identity %q:\n", a.MatchedID)
		}
		saved := tw.indent
		tw.indent += 3
		tw.renderGroup(a.NestedTrace)
		tw.indent = saved
		return
	}
	tw.printf("    No identity matched → FAIL\n")
}

// flattenProperties converts nested properties to a sorted list of "key: value" strings.
func flattenProperties(props map[string]any, prefix string, lines *[]string) {
	for k, v := range props {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		if nested, ok := v.(map[string]any); ok {
			flattenProperties(nested, fullKey, lines)
		} else {
			*lines = append(*lines, fmt.Sprintf("%s: %s", fullKey, formatValue(v)))
		}
	}
}
