package lint

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// Dir discovers YAML files under root and lints them all.
// readFile must enforce size limits (e.g., fsutil.ReadFileLimited).
// It returns a sorted slice of diagnostics.
func Dir(ctx context.Context, root string, readFile func(string) ([]byte, error)) ([]Diagnostic, error) {
	files, err := CollectYAMLFiles(ctx, root)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no control YAML files found in %s", root)
	}

	linter := NewLinter()
	var (
		mu  sync.Mutex
		all []Diagnostic
	)

	g, gctx := errgroup.WithContext(ctx)
	for _, file := range files {
		g.Go(func() error {
			if err := gctx.Err(); err != nil {
				return fmt.Errorf("lint cancelled: %w", err)
			}
			clean := filepath.Clean(file)
			data, readErr := readFile(clean)
			if readErr != nil {
				return fmt.Errorf("read %s: %w", clean, readErr)
			}
			diags := linter.LintBytes(file, data)
			mu.Lock()
			all = append(all, diags...)
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("lint files: %w", err)
	}

	SortDiagnostics(all)
	return all, nil
}

// CollectYAMLFiles discovers YAML files at the given path.
// If root is a file, it returns that file (if it has a YAML extension).
// If root is a directory, it walks recursively.
func CollectYAMLFiles(ctx context.Context, root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", root, err)
	}
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(root))
		if ext == ".yaml" || ext == ".yml" {
			return []string{root}, nil
		}
		return nil, fmt.Errorf("unsupported file type %q", root)
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("collect YAML cancelled: %w", ctxErr)
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", root, err)
	}
	slices.Sort(files)
	return files, nil
}

// SortDiagnostics sorts diagnostics by path, line, column, rule ID, then message.
func SortDiagnostics(diags []Diagnostic) {
	slices.SortFunc(diags, CompareDiagnostic)
}

// CompareDiagnostic defines canonical ordering for diagnostics.
func CompareDiagnostic(a, b Diagnostic) int {
	if c := cmp.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	if a.Line != b.Line {
		return a.Line - b.Line
	}
	if a.Col != b.Col {
		return a.Col - b.Col
	}
	if c := cmp.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}
	return cmp.Compare(a.Message, b.Message)
}

// ErrorCount returns the number of error-severity diagnostics.
func ErrorCount(diags []Diagnostic) int {
	n := 0
	for i := range diags {
		if diags[i].IsError() {
			n++
		}
	}
	return n
}
