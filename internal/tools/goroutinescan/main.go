// Command goroutinescan reports raw goroutine launches (`go` statements) in the
// Stave Go source and flags each one whose enclosing function shows no
// lifecycle-management signal — errgroup, sync.WaitGroup, context cancellation,
// or a received result channel. A flagged goroutine ("managed": false) is a
// HEURISTIC candidate that NEEDS MANUAL CONFIRMATION, not a confirmed defect.
//
// The signal scan is function-body-scoped and name-based (not type-checked), so
// it intentionally errs toward "managed" and has two known blind spots: (1) an
// incidental lifecycle signal — or one managing a DIFFERENT goroutine in the
// same function — marks a fire-and-forget launch as managed, so the unmanaged
// count is a FLOOR, not a ceiling; (2) teardown extracted to a sibling method
// (Begin/loop/End sharing channels on a receiver) reads as unmanaged. errgroup
// used only via a passed-in group (g.Go) and signal.NotifyContext are not
// detected. All of these need manual review of a flagged or unflagged launch.
//
// It is the DIM4 detector of the report-only Go best-practices audit; see
// docs/superpowers/specs/2026-06-13-go-best-practices-audit-design.md.
//
// Usage:
//
//	go run ./internal/tools/goroutinescan -root . > goroutines.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const schemaVersion = "goroutinescan.v1"

// Goroutine is one `go` statement and the verdict on whether its enclosing
// function manages the goroutine's lifecycle.
type Goroutine struct {
	File    string   `json:"file"`
	Line    int      `json:"line"`
	Func    string   `json:"func"`
	Managed bool     `json:"managed"`
	Signals []string `json:"signals"`
}

// Summary is the aggregate count across all scanned files.
type Summary struct {
	Total     int `json:"total"`
	Unmanaged int `json:"unmanaged"`
}

// Result is the full deterministic JSON document emitted on stdout.
type Result struct {
	Schema     string      `json:"schema"`
	Goroutines []Goroutine `json:"goroutines"`
	Summary    Summary     `json:"summary"`
}

type config struct {
	Root string
	Out  io.Writer
}

func main() {
	root := flag.String("root", ".", "module root to scan")
	flag.Parse()
	if err := run(config{Root: *root, Out: os.Stdout}); err != nil {
		fmt.Fprintln(os.Stderr, "goroutinescan:", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	gs, err := scanDir(cfg.Root)
	if err != nil {
		return err
	}
	if gs == nil {
		gs = []Goroutine{}
	}
	res := Result{Schema: schemaVersion, Goroutines: gs, Summary: Summary{Total: len(gs)}}
	for _, g := range gs {
		if !g.Managed {
			res.Summary.Unmanaged++
		}
	}
	enc := json.NewEncoder(cfg.Out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	return nil
}

// skipDir reports directories that are never part of the library surface.
func skipDir(name string) bool {
	switch name {
	case "vendor", "testdata", "fixtures", "examples", ".git", "node_modules":
		return true
	}
	return false
}

var generatedRe = regexp.MustCompile(`(?m)^// Code generated .* DO NOT EDIT\.?$`)

// isGenerated reports whether src carries the standard generated-file marker.
func isGenerated(src []byte) bool {
	head := src
	if len(head) > 4096 {
		head = head[:4096]
	}
	return generatedRe.Match(head)
}

// scanDir walks root and scans every non-test, non-generated .go file,
// returning goroutines sorted by (file, line) for deterministic output.
func scanDir(root string) ([]Goroutine, error) {
	var out []Goroutine
	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("read %s: %w", rel, rerr)
		}
		if isGenerated(src) {
			return nil
		}
		gs, serr := scanFileSource(fset, rel, src)
		if serr != nil {
			return fmt.Errorf("scan %s: %w", rel, serr)
		}
		out = append(out, gs...)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out, nil
}

// funcRange records a function's source span so a `go` statement can be matched
// to its innermost enclosing function (signal scope) and declaration (name).
type funcRange struct {
	pos    token.Pos
	end    token.Pos
	name   string
	body   *ast.BlockStmt
	isDecl bool
}

func (f funcRange) span() token.Pos { return f.end - f.pos }

func (f funcRange) contains(p token.Pos) bool { return f.pos <= p && p < f.end }

// scanFileSource parses one Go source file and returns the goroutines it
// launches, each annotated with the lifecycle signals found in the enclosing
// function. relPath populates the File field.
func scanFileSource(fset *token.FileSet, relPath string, src []byte) ([]Goroutine, error) {
	f, err := parser.ParseFile(fset, relPath, src, 0)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	var fns []funcRange
	var gostmts []*ast.GoStmt
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if x.Body != nil {
				fns = append(fns, funcRange{x.Pos(), x.End(), declName(x), x.Body, true})
			}
		case *ast.FuncLit:
			fns = append(fns, funcRange{x.Pos(), x.End(), "", x.Body, false})
		case *ast.GoStmt:
			gostmts = append(gostmts, x)
		}
		return true
	})

	var out []Goroutine
	for _, g := range gostmts {
		p := g.Pos()
		var scope *funcRange // innermost function of any kind (signal scope)
		var named *funcRange // innermost named declaration (reporting name)
		for i := range fns {
			fn := &fns[i]
			if !fn.contains(p) {
				continue
			}
			if scope == nil || fn.span() < scope.span() {
				scope = fn
			}
			if fn.isDecl && (named == nil || fn.span() < named.span()) {
				named = fn
			}
		}
		name := "(anonymous)"
		if named != nil {
			name = named.name
		}
		var signals []string
		if scope != nil {
			signals = scanSignals(scope.body)
		}
		managed := len(signals) > 0
		if signals == nil {
			signals = []string{} // emit [] not null for clean, jq-parseable output
		}
		out = append(out, Goroutine{
			File:    relPath,
			Line:    fset.Position(p).Line,
			Func:    name,
			Managed: managed,
			Signals: signals,
		})
	}
	return out, nil
}

// declName renders a function declaration name, prefixing the receiver type for
// methods so report rows are unambiguous (e.g. "Engine.Run").
func declName(fd *ast.FuncDecl) string {
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		if recv := receiverType(fd.Recv.List[0].Type); recv != "" {
			return recv + "." + fd.Name.Name
		}
	}
	return fd.Name.Name
}

func receiverType(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.StarExpr:
		return receiverType(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr: // generic receiver, e.g. Engine[T]
		return receiverType(x.X)
	case *ast.IndexListExpr:
		return receiverType(x.X)
	}
	return ""
}

// scanSignals inspects a function body for lifecycle-management signals and
// returns their sorted labels. An empty result means the goroutine appears
// unmanaged (a heuristic candidate for manual review).
func scanSignals(body *ast.BlockStmt) []string {
	if body == nil {
		return nil
	}
	set := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			switch x.Name {
			case "errgroup":
				set["errgroup"] = true
			case "WaitGroup":
				set["waitgroup"] = true
			case "context":
				set["context"] = true
			}
		case *ast.SelectorExpr:
			switch x.Sel.Name {
			case "WaitGroup", "Wait":
				set["waitgroup"] = true
			case "Done":
				set["done"] = true
			}
		case *ast.UnaryExpr:
			if x.Op == token.ARROW { // channel receive: awaiting a result
				set["chan-recv"] = true
			}
		}
		return true
	})
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
