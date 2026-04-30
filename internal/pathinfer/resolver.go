// Package pathinfer provides path inference for Stave CLI flags.
// It resolves conventional directory names from the working directory
// or STAVE_PROJECT_ROOT environment variable.
package pathinfer

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/env"
)

// BaseDir returns the base directory for path inference.
// If STAVE_PROJECT_ROOT is set and points to a valid directory, it is
// returned. Otherwise, the current working directory is returned.
// The environ parameter controls environment lookups (pass os.Getenv
// in production; inject a stub in tests).
func BaseDir(environ ...func(string) string) (string, error) {
	lookup := os.Getenv
	if len(environ) > 0 && environ[0] != nil {
		lookup = environ[0]
	}
	if root := lookup(env.ProjectRoot.Name); root != "" {
		fi, err := os.Stat(root)
		if err == nil && fi.IsDir() {
			return root, nil
		}
	}
	return os.Getwd()
}

// Unique looks for a directory named name under base.
//
// Resolution order:
//  1. If base/name/ exists, return it immediately.
//  2. Walk base up to maxDepth levels looking for directories named exactly name.
//  3. If exactly 1 match is found, return it.
//  4. If 0 matches are found, return an error listing conventions.
//  5. If >1 matches are found, return an error listing all candidates (sorted, relative to base).
//
// The second return value contains the candidate paths (relative to base) when
// multiple matches are found, or nil otherwise.
func Unique(base, name string, maxDepth int) (string, []string, error) {
	direct := filepath.Join(base, name)
	if isDir(direct) {
		return direct, nil, nil
	}
	candidates, err := dirCandidates(base, name, maxDepth)
	if err != nil {
		return "", nil, err
	}
	slices.Sort(candidates)
	return resolveCandidates(resolutionRequest{
		Base:       base,
		Name:       name,
		MaxDepth:   maxDepth,
		DirectPath: direct,
		Candidates: candidates,
	})
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func dirCandidates(base, name string, maxDepth int) ([]string, error) {
	walker := &walkState{
		base:     base,
		name:     name,
		maxDepth: maxDepth,
	}
	if err := filepath.WalkDir(base, walker.walk); err != nil {
		return walker.candidates, fmt.Errorf("walk %s: %w", base, err)
	}
	// Surface non-fatal walk errors at Warn so a permission-denied
	// subtree doesn't silently turn a missing-control-dir into an
	// empty-candidate-list misdiagnosis.
	for _, we := range walker.Errors() {
		slog.Warn("pathinfer: skipping unreadable entry during walk",
			"path", we.Path, "error", we.Err)
	}
	return walker.candidates, nil
}

type walkState struct {
	base       string
	name       string
	maxDepth   int
	candidates []string
	walkErrs   []walkErr // accumulated non-fatal traversal errors
}

// walkErr records a non-fatal error encountered during the directory
// walk. The walker keeps going (best-effort search) but these are
// surfaced to the caller via Errors() so an operator can tell when
// the search saw a permission-denied subtree they didn't intend to
// hide.
type walkErr struct {
	Path string
	Err  error
}

// Errors returns the non-fatal walk errors collected during walk.
// Empty slice when the walk completed without skipping any subtree.
func (s *walkState) Errors() []walkErr { return s.walkErrs }

func (s *walkState) walk(path string, entry fs.DirEntry, walkErrIn error) error {
	if walkErrIn != nil {
		// Permission denied / bad symlink / vanished entry — keep
		// walking but record so the operator can see what was
		// skipped. Returning nil signals filepath.WalkDir to continue
		// past this entry.
		s.walkErrs = append(s.walkErrs, walkErr{Path: path, Err: walkErrIn})
		return nil //nolint:nilerr // intentional: best-effort walk continues, error captured on walkState
	}
	if !entry.IsDir() {
		return nil
	}

	// Skip hidden directories (.git, .stave, etc.) to save I/O.
	if name := entry.Name(); strings.HasPrefix(name, ".") && name != "." {
		return fs.SkipDir
	}

	rel, err := filepath.Rel(s.base, path)
	if err != nil || rel == "." {
		return nil //nolint:nilerr // Rel failure on a walk entry is non-fatal
	}

	depth := pathDepth(rel)
	if entry.Name() == s.name {
		if depth <= s.maxDepth {
			s.candidates = append(s.candidates, path)
		}
		return fs.SkipDir
	}
	if depth >= s.maxDepth {
		return fs.SkipDir
	}
	return nil
}

// pathDepth counts directory separators in the cleaned relative path.
// "a" = 0, "a/b" = 1, "a/b/c" = 2.
func pathDepth(rel string) int {
	rel = filepath.Clean(rel)
	if rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator))
}

type resolutionRequest struct {
	Base       string
	Name       string
	MaxDepth   int
	DirectPath string
	Candidates []string
}

func resolveCandidates(req resolutionRequest) (string, []string, error) {
	switch len(req.Candidates) {
	case 0:
		return "", nil, fmt.Errorf(
			"no %q directory found under %s (expected %s or a nested %s/ within %d levels)",
			req.Name, req.Base, req.DirectPath, req.Name, req.MaxDepth,
		)
	case 1:
		return req.Candidates[0], nil, nil
	default:
		relCandidates := relativePaths(req.Base, req.Candidates)
		return "", relCandidates, fmt.Errorf(
			"ambiguous: found %d %q directories under %s: %s",
			len(req.Candidates), req.Name, req.Base, strings.Join(relCandidates, ", "),
		)
	}
}

func relativePaths(base string, paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		rel, err := filepath.Rel(base, p)
		if err != nil {
			slog.Debug("cannot compute relative path, using absolute", "base", base, "path", p, "error", err)
			out[i] = p
			continue
		}
		out[i] = rel
	}
	return out
}
