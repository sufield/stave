// renderer_pattern_test.go — the mechanical guard behind CLAUDE.md New
// Command Checklist item 7 (the Renderer pattern). Format dispatch must
// go through a NewRenderer factory living in a renderer*.go file, never
// inline in a command handler. It catches all four syntactic forms the
// 2026-06-07 audits found: a tagged `switch opts.Format`, a tagless
// `switch { case f.IsJSON(): }`, an `if opts.Format == "json" { …encode… }`,
// and the typed `if f.IsJSON() { …encode… }`.
//
// A failing test is the gate that doesn't blink.
//
//	go test ./cmd -run TestNoInlineFormatSwitch
package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// formatSwitchAllowlist names the files under cmd/ that contain a
// `switch` on a format value which is NOT inline render dispatch, and is
// therefore exempt. Keyed by path relative to cmd/. Every entry must say
// why it is exempt. A dead entry (the file no longer has a format-switch)
// fails the test, so the list cannot quietly rot.
//
// renderer*.go files are skipped wholesale — they ARE the factories, so a
// `switch format` returning concrete Renderer types is exactly right
// there and never needs an allowlist entry.
var formatSwitchAllowlist = map[string]string{
	"cmdutil/compose/output.go": "DefaultFindingWriter IS the FindingWriterFactory: the switch maps format " +
		"strings to concrete FindingMarshaler types and returns them. A factory, not inline dispatch.",
	"mcp/main.go": "MCP JSON-RPC server (deliberately SDK-free protocol dispatcher): the switch maps " +
		"tool args to MCP envelopes, not Renderer types. Out of scope of the cmd/ Renderer pattern.",
}

func TestNoInlineFormatSwitch(t *testing.T) {
	fset := token.NewFileSet()
	found := map[string][]string{} // relpath -> positions of format-switches

	walkErr := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		// renderer*.go ARE the factories; *_test.go (incl. this file) carry
		// the rule's own vocabulary and must not match themselves.
		if !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") ||
			strings.HasPrefix(name, "renderer") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel := filepath.ToSlash(path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SwitchStmt:
				// Tagged `switch opts.Format` OR tagless `switch { case
				// f.IsJSON(): }` — both are format dispatch.
				if (node.Tag != nil && switchesOnFormat(node.Tag)) ||
					(node.Tag == nil && taglessSwitchOnFormat(node)) {
					found[rel] = append(found[rel], fset.Position(node.Switch).String())
				}
			case *ast.IfStmt:
				// `if opts.Format == "json" { ...encode... }` / `if
				// f.IsJSON() { ...encode... }` — an if that branches on a
				// format value AND renders (JSON-encodes) in the branch is
				// the same dispatch. The encode test separates real dispatch
				// from the legitimate "suppress human hints in JSON mode"
				// idiom, which never encodes.
				if node.Cond != nil && exprReferencesFormat(node.Cond) && rendersInBody(node.Body) {
					found[rel] = append(found[rel], fset.Position(node.If).String())
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}

	// 1. A format-switch in any non-allowlisted file is a violation.
	var offences []string
	for rel, positions := range found {
		if _, ok := formatSwitchAllowlist[rel]; ok {
			continue
		}
		offences = append(offences, positions...)
	}
	slices.Sort(offences)
	if len(offences) > 0 {
		t.Errorf("inline format dispatch (switch / tagless-switch / if-encode) found outside a renderer*.go factory (%d):\n  %s\n\n"+
			"Format dispatch must go through a NewRenderer factory in a renderer*.go file: one Renderer\n"+
			"interface, one concrete type per format, one factory mapping the format once (unknown -> error).\n"+
			"Reference: cmd/export/compliance/renderer.go.\n"+
			"If a flagged site is genuinely not render dispatch (a factory, a validation switch, or an\n"+
			"out-of-scope surface), add its file to formatSwitchAllowlist with a reason.",
			len(offences), strings.Join(offences, "\n  "))
	}

	// 2. The allowlist may not rot: every entry must still name a file
	// that currently contains a format-switch.
	for rel := range formatSwitchAllowlist {
		if len(found[rel]) == 0 {
			t.Errorf("stale formatSwitchAllowlist entry %q: the file no longer contains a "+
				"format-switch; remove the entry.", rel)
		}
	}
}

// switchesOnFormat reports whether a switch tag dispatches on a format
// VALUE — the identifier `format` (any case, any *Format suffix) or a
// selector ending in `Format` (opts.Format, args.Format, req.OutputFormat).
// It deliberately ignores type conversions like `Format(ui.NormalizeToken(s))`
// and switches on a differently named local (e.g. `switch normalized` in
// graph.ParseFormat): those are validation switches, not the
// `switch opts.Format` render-dispatch anti-pattern item 7 forbids.
func switchesOnFormat(tag ast.Expr) bool {
	switch e := tag.(type) {
	case *ast.Ident:
		return strings.HasSuffix(strings.ToLower(e.Name), "format")
	case *ast.SelectorExpr:
		return e.Sel != nil && strings.HasSuffix(e.Sel.Name, "Format")
	}
	return false
}

// taglessSwitchOnFormat reports whether a tagless `switch {}` branches on a
// format value in its case conditions (e.g. `case opts.Format.IsJSON():` or
// `case r.Format != "" && r.Format != string(FormatText):`). Same dispatch
// anti-pattern as a tagged `switch opts.Format`, written as a conditionless
// switch — the form cmd/apply/lint and cmd/scorecard used to slip past the
// tagged-switch check.
func taglessSwitchOnFormat(sw *ast.SwitchStmt) bool {
	if sw.Body == nil {
		return false
	}
	for _, stmt := range sw.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if slices.ContainsFunc(cc.List, exprReferencesFormat) {
			return true
		}
	}
	return false
}

// exprReferencesFormat reports whether an expression mentions a format value:
// an identifier whose name ends in `format` (any case) or a selector ending in
// `Format` (opts.Format, f.Format). It also catches `.IsJSON()` / `.IsMarkdown()`
// method calls on a format value via the receiver selector. It does NOT match
// the type constant `FormatText` (lowercases to "formattext", which does not
// end in "format").
func exprReferencesFormat(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if strings.HasSuffix(strings.ToLower(x.Name), "format") {
				found = true
			}
		case *ast.SelectorExpr:
			if x.Sel != nil && (strings.HasSuffix(x.Sel.Name, "Format") ||
				x.Sel.Name == "IsJSON" || x.Sel.Name == "IsMarkdown" || x.Sel.Name == "IsText") {
				found = true
			}
		}
		return !found
	})
	return found
}

// rendersInBody reports whether a block JSON-encodes — a call to Encode,
// NewEncoder, Marshal, MarshalIndent, or *.WriteIndented. Used to tell a real
// `if opts.Format.IsJSON() { encode... }` dispatch branch from the legitimate
// hint-suppression idiom (`if format.IsJSON() { return }`), which never
// encodes. A renderer*.go factory is the right home for the encode.
func rendersInBody(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	encoders := map[string]struct{}{
		"Encode": {}, "NewEncoder": {}, "Marshal": {},
		"MarshalIndent": {}, "WriteIndented": {},
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil {
			if _, hit := encoders[sel.Sel.Name]; hit {
				found = true
			}
		}
		return !found
	})
	return found
}
