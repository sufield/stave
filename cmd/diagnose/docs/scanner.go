package docs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// docsFile represents a discovered documentation file.
type docsFile struct {
	Abs string
	Rel string
}

func collectDocsFiles(root string, include []string) ([]docsFile, error) {
	root = fsutil.CleanUserPath(root)
	seen := make(map[string]struct{})
	var files []docsFile

	for _, rawPath := range include {
		includePath := strings.TrimSpace(rawPath)
		if includePath == "" {
			continue
		}
		full := fsutil.CleanUserPath(filepath.Join(root, includePath))
		info, err := os.Stat(full)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("cannot access %s: %w", includePath, err)
		}
		if info.Mode().IsRegular() {
			appendDocFileIfEligible(root, full, seen, &files)
			continue
		}
		if !info.IsDir() {
			continue
		}
		if err := appendDocsFromDirectory(root, full, seen, &files); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(files, func(a, b docsFile) int {
		return strings.Compare(a.Rel, b.Rel)
	})
	return files, nil
}

func appendDocFileIfEligible(root, abs string, seen map[string]struct{}, files *[]docsFile) {
	if !isDocFile(abs) {
		return
	}
	rel := relativeDocPath(root, abs)
	if _, ok := seen[rel]; ok {
		return
	}
	seen[rel] = struct{}{}
	*files = append(*files, docsFile{Abs: abs, Rel: rel})
}

func appendDocsFromDirectory(root, dir string, seen map[string]struct{}, files *[]docsFile) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		appendDocFileIfEligible(root, path, seen, files)
		return nil
	})
}

func relativeDocPath(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	return filepath.ToSlash(rel)
}

func isDocFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".md", ".txt", ".rst", ".adoc":
		return true
	default:
		return false
	}
}
