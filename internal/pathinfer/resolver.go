// Package pathinfer provides path inference for Stave CLI flags.
// It resolves conventional directory names from the working directory
// or STAVE_PROJECT_ROOT environment variable.
package pathinfer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/envvar"
)

// BaseDir returns the base directory for path inference.
// If STAVE_PROJECT_ROOT is set and points to a valid directory, it is returned.
// Otherwise, the current working directory is returned.
func BaseDir() (string, error) {
	if root := os.Getenv(envvar.ProjectRoot.Name); root != "" {
		// #nosec G703 -- STAVE_PROJECT_ROOT is an explicit local override and is only checked for existence/type.
		fi, err := os.Stat(root)
		if err == nil && fi.IsDir() {
			return root, nil
		}
		// Invalid STAVE_PROJECT_ROOT — fall through to cwd
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
	if directPath, ok := findDirectPath(direct); ok {
		return directPath, nil, nil
	}
	candidates, err := dirCandidates(base, name, maxDepth)
	if err != nil {
		return "", nil, err
	}
	sort.Strings(candidates)
	return resolveCandidates(resolutionRequest{
		Base:       base,
		Name:       name,
		MaxDepth:   maxDepth,
		DirectPath: direct,
		Candidates: candidates,
	})
}

func findDirectPath(path string) (string, bool) {
	fi, err := os.Stat(path)
	if err == nil && fi.IsDir() {
		return path, true
	}
	return "", false
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
	return walker.candidates, nil
}

type walkState struct {
	base       string
	name       string
	maxDepth   int
	candidates []string
}

func (s *walkState) walk(path string, entry fs.DirEntry, walkErr error) error {
	if walkErr != nil || !entry.IsDir() {
		return nil
	}
	rel, ok := relativeWalkPath(s.base, path)
	if !ok || rel == "." {
		return nil
	}
	// Use forward slashes for consistent depth counting across platforms.
	depth := strings.Count(filepath.ToSlash(rel), "/")
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

func relativeWalkPath(base, path string) (string, bool) {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return "", false
	}
	return rel, true
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
		relCandidates := relativeCandidatePaths(req.Base, req.Candidates)
		return "", relCandidates, fmt.Errorf(
			"ambiguous: found %d %q directories under %s: %s",
			len(req.Candidates), req.Name, req.Base, strings.Join(relCandidates, ", "),
		)
	}
}

func relativeCandidatePaths(base string, candidates []string) []string {
	relative := make([]string, len(candidates))
	for i, candidate := range candidates {
		r, err := filepath.Rel(base, candidate)
		if err != nil {
			relative[i] = candidate
			continue
		}
		relative[i] = r
	}
	return relative
}
