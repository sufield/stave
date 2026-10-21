package universals

import (
	"fmt"
	"regexp"
	"strings"
)

type asset struct {
	ID         string
	Type       string
	Properties map[string]any
}

type grounded struct {
	name  string
	preds map[string]bool
}

var nonAlpha = regexp.MustCompile(`[^a-zA-Z0-9]`)

func smtName(id string) string {
	s := nonAlpha.ReplaceAllString(id, "_")
	if len(s) > 50 {
		s = s[len(s)-50:]
	}
	return "c_" + s
}

// GroundAssets converts observation assets into SMT-LIB grounded constants
// using the grounding map for a specific universal.
func GroundAssets(assets []asset, ug UniversalGrounding) []grounded {
	var out []grounded
	for _, a := range assets {
		atg, ok := ug.Groundings[a.Type]
		if !ok {
			continue
		}

		if whenVal, hasWhen := atg["when"]; hasWhen {
			whenPath, _ := whenVal.(string)
			if whenPath != "" && getMap(a.Properties, parsePath(whenPath)...) == nil {
				continue
			}
		}

		preds := make(map[string]bool)
		for _, pred := range ug.Predicates {
			val, ok := atg[pred]
			if !ok {
				continue
			}
			preds[pred] = resolvePredicate(val, a.Properties)
		}
		out = append(out, grounded{smtName(a.ID), preds})
	}
	return out
}

func resolvePredicate(val any, props map[string]any) bool {
	switch v := val.(type) {
	case bool:
		return v
	case string:
		if strings.HasPrefix(v, "!.") {
			return !getBool(props, parsePath(v[1:])...)
		}
		if strings.HasPrefix(v, ".") {
			return getBool(props, parsePath(v)...)
		}
		return false
	default:
		return false
	}
}

func parsePath(dotPath string) []string {
	s := strings.TrimPrefix(dotPath, ".")
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

func getBool(props map[string]any, path ...string) bool {
	cur := props
	for i, key := range path {
		v, ok := cur[key]
		if !ok {
			return false
		}
		if i == len(path)-1 {
			b, _ := v.(bool)
			return b
		}
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		cur = m
	}
	return false
}

func getMap(props map[string]any, path ...string) map[string]any {
	cur := props
	for _, key := range path {
		v, ok := cur[key]
		if !ok {
			return nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		cur = m
	}
	return cur
}

// GenerateGrounding produces SMT-LIB assertions from grounded constants,
// including universe closure (finite domain).
func GenerateGrounding(sortName string, preds []string, gs []grounded) string {
	var buf strings.Builder

	if len(gs) == 0 {
		fmt.Fprintf(&buf, "; no %s assets — precondition false for all\n", sortName)
		fmt.Fprintf(&buf, "(assert (forall ((x %s)) (not (%s x))))\n", sortName, preds[0])
		return buf.String()
	}

	for _, g := range gs {
		fmt.Fprintf(&buf, "(declare-const %s %s)\n", g.name, sortName)
	}

	if len(gs) > 1 {
		names := make([]string, len(gs))
		for i, g := range gs {
			names[i] = g.name
		}
		fmt.Fprintf(&buf, "(assert (distinct %s))\n", strings.Join(names, " "))
	}

	var clauses []string
	for _, g := range gs {
		clauses = append(clauses, fmt.Sprintf("(= x %s)", g.name))
	}
	var closure string
	if len(clauses) == 1 {
		closure = clauses[0]
	} else {
		closure = fmt.Sprintf("(or %s)", strings.Join(clauses, " "))
	}
	fmt.Fprintf(&buf, "(assert (forall ((x %s)) %s))\n", sortName, closure)

	for _, g := range gs {
		for _, pred := range preds {
			val, ok := g.preds[pred]
			if !ok {
				continue
			}
			if val {
				fmt.Fprintf(&buf, "(assert (%s %s))\n", pred, g.name)
			} else {
				fmt.Fprintf(&buf, "(assert (not (%s %s)))\n", pred, g.name)
			}
		}
	}

	return buf.String()
}
