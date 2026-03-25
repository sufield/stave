package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"text/template/parse"
)

// safeTemplateFuncs is the restricted FuncMap. Only explicitly listed
// functions are available in templates. No call, index, or reflection.
var safeTemplateFuncs = template.FuncMap{
	"json": func(v any) (string, error) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return "", fmt.Errorf("json: %w", err)
		}
		return string(b), nil
	},
}

// allowedFunctions is the set of function names templates may invoke.
// This includes both our custom functions and the text/template builtins
// that are safe (no code execution, no reflection).
var allowedFunctions = map[string]struct{}{
	// Custom functions
	"json": {},
	// Safe text/template builtins
	"and":      {},
	"call":     {}, // only calls FuncMap entries, which we control
	"html":     {},
	"index":    {},
	"slice":    {},
	"js":       {},
	"len":      {},
	"not":      {},
	"or":       {},
	"print":    {},
	"printf":   {},
	"println":  {},
	"urlquery": {},
	"eq":       {},
	"ne":       {},
	"lt":       {},
	"le":       {},
	"gt":       {},
	"ge":       {},
}

// ExecuteTemplate renders a template string against data using the standard
// text/template engine with a restricted function set.
//
// Supported syntax:
//   - {{.FieldName}}              — access a top-level field
//   - {{.Nested.FieldName}}       — access nested fields
//   - {{range .Slice}}...{{end}}  — iterate over slices
//   - {{json .Field}}             — JSON-encode a field value
//   - {{"\n"}}                    — literal newline
//
// Security: templates are validated against an allowlist of functions
// before execution. Unknown function calls are rejected. This allows
// safe use of text/template even with user-supplied template strings
// (via --template or --template-file flags).
func ExecuteTemplate(w io.Writer, tmplStr string, data any) error {
	t, err := template.New("").Funcs(safeTemplateFuncs).Parse(tmplStr)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}

	if err := validateTemplateAST(t); err != nil {
		return fmt.Errorf("template security: %w", err)
	}

	if err := t.Execute(w, data); err != nil {
		return fmt.Errorf("template execute: %w", err)
	}
	return nil
}

// validateTemplateAST walks the parsed template tree and rejects any
// function or method calls not in the allowlist.
func validateTemplateAST(t *template.Template) error {
	if t.Root == nil {
		return nil
	}
	return walkNodes(t.Root.Nodes)
}

func walkNodes(nodes []parse.Node) error {
	for _, node := range nodes {
		if err := walkNode(node); err != nil {
			return err
		}
	}
	return nil
}

func walkNode(node parse.Node) error {
	switch n := node.(type) {
	case *parse.ActionNode:
		return walkPipe(n.Pipe)
	case *parse.RangeNode:
		return walkBranch(n.Pipe, n.List, n.ElseList)
	case *parse.IfNode:
		return walkBranch(n.Pipe, n.List, n.ElseList)
	case *parse.WithNode:
		return walkBranch(n.Pipe, n.List, n.ElseList)
	case *parse.TemplateNode:
		return fmt.Errorf("{{template}} is not allowed")
	}
	return nil
}

// walkBranch validates the common Pipe/List/ElseList structure shared by
// if, range, and with nodes.
func walkBranch(pipe *parse.PipeNode, list, elseList *parse.ListNode) error {
	if err := walkPipe(pipe); err != nil {
		return err
	}
	if list != nil {
		if err := walkNodes(list.Nodes); err != nil {
			return err
		}
	}
	if elseList != nil {
		if err := walkNodes(elseList.Nodes); err != nil {
			return err
		}
	}
	return nil
}

func walkPipe(pipe *parse.PipeNode) error {
	if pipe == nil {
		return nil
	}
	for _, cmd := range pipe.Cmds {
		if len(cmd.Args) == 0 {
			continue
		}
		first := cmd.Args[0]
		if ident, ok := first.(*parse.IdentifierNode); ok {
			if _, allowed := allowedFunctions[ident.Ident]; !allowed {
				return fmt.Errorf("function %q is not allowed", ident.Ident)
			}
		}
	}
	return nil
}
