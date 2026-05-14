// Package pathinfer provides path inference for Stave CLI flags.
// It resolves conventional directory names from the working directory
// or STAVE_PROJECT_ROOT environment variable.
package pathinfer

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/env"
)

// Sentinel errors so callers can use errors.Is to react to specific
// resolution outcomes (e.g. show a setup hint when no candidate exists,
// or prompt the user to disambiguate when multiple candidates exist).
var (
	ErrNoCandidate         = errors.New("pathinfer: no matching directory found")
	ErrAmbiguousCandidates = errors.New("pathinfer: multiple matching directories found")
)

// BaseDir returns the base directory for path inference.
//
// Resolution order:
//  1. If STAVE_PROJECT_ROOT is set and points to a valid directory,
//     return it.
//  2. If STAVE_PROJECT_ROOT is set but invalid (missing path,
//     not-a-directory, permission error), log a warning and fall
//     back to the current working directory. The earlier shape
//     fell back silently, which made operator typos in the
//     environment invisible — runs that should have used a
//     specific project root quietly resolved relative to wherever
//     the binary happened to be invoked.
//  3. Otherwise, return the current working directory.
//
// The environ parameter controls environment lookups (pass os.Getenv
// in production; inject a stub in tests).
//
// Optional BaseDirOption values let callers swap the cwd lookup —
// useful for tests that need a deterministic fallback without
// chdir'ing the process.
func BaseDir(opts ...BaseDirOption) (string, error) {
	cfg := baseDirConfig{
		lookup: os.Getenv,
		getwd:  os.Getwd,
	}
	for _, o := range opts {
		o(&cfg)
	}
	if root := cfg.lookup(env.ProjectRoot.Name); root != "" {
		fi, err := os.Stat(root)
		switch {
		case err != nil:
			slog.Warn("STAVE_PROJECT_ROOT is set but the path could not be statted; falling back to cwd",
				"path", root, "error", err)
		case !fi.IsDir():
			slog.Warn("STAVE_PROJECT_ROOT is set but the path is not a directory; falling back to cwd",
				"path", root)
		default:
			return root, nil
		}
	}
	return cfg.getwd()
}

// BaseDirOption configures BaseDir's lookup hooks.
type BaseDirOption func(*baseDirConfig)

type baseDirConfig struct {
	lookup func(string) string
	getwd  func() (string, error)
}

// WithEnviron overrides the env-lookup function (defaults to os.Getenv).
func WithEnviron(lookup func(string) string) BaseDirOption {
	return func(c *baseDirConfig) {
		if lookup != nil {
			c.lookup = lookup
		}
	}
}

// WithGetwd overrides the cwd-lookup function (defaults to os.Getwd).
// Tests that exercise the STAVE_PROJECT_ROOT-unset / fallback path
// inject a deterministic getwd here instead of chdir'ing the test
// process.
func WithGetwd(getwd func() (string, error)) BaseDirOption {
	return func(c *baseDirConfig) {
		if getwd != nil {
			c.getwd = getwd
		}
	}
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
	// fs.DirEntry.IsDir() returns false for a symlink that *points
	// at* a directory, because IsDir reads the entry's own type
	// bits rather than following the link. The earlier shape
	// stopped walking through any symlinked directory — so the
	// common pattern `controls -> ../shared/controls` made the
	// directory-name match impossible because the symlink entry
	// looked like a non-directory.
	//
	// What this branch does and does NOT do:
	//   - DOES treat a directory-targeting symlink as a directory
	//     for the rest of this function (so its name can satisfy
	//     the search-for-`name` predicate below).
	//   - DOES NOT descend into the target directory's contents.
	//     filepath.WalkDir does not follow symlinks regardless of
	//     what we return here, so a symlinked directory is
	//     visible AS a candidate but its inner files are not
	//     reached. To inspect inner contents, the caller must
	//     pass the resolved path explicitly.
	if entry.Type()&fs.ModeSymlink != 0 {
		info, err := os.Stat(path)
		if err != nil {
			// nilerr: the error is captured on s.walkErrs for the
			// caller to inspect; returning it would abort the whole
			// walk on a single broken symlink, which is exactly
			// what we want to avoid.
			s.walkErrs = append(s.walkErrs, walkErr{Path: path, Err: err})
			return nil //nolint:nilerr // intentional: error captured on s.walkErrs so the walk can continue past a single broken symlink
		}
		if !info.IsDir() {
			return nil
		}
		// fall through to treat-as-directory
	} else if !entry.IsDir() {
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
		} else {
			// Operators investigating "why didn't Stave find my
			// directory?" benefit from a debug log naming the
			// excluded path and the depth budget — the search
			// otherwise looks like the directory genuinely doesn't
			// exist.
			slog.Debug("pathinfer: candidate excluded by depth limit",
				"path", path, "depth", depth, "max_depth", s.maxDepth)
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
//
// Strips the volume name (Windows "C:" or `\\host\share` UNC prefix)
// before counting so a path like `C:\stave\controls` reports depth
// 1 — same as POSIX `stave/controls`. Without the strip, the volume
// adds spurious separators on Windows and a depth-2 budget would
// reject every Windows search path.
func pathDepth(rel string) int {
	rel = filepath.Clean(rel)
	rel = strings.TrimPrefix(rel, filepath.VolumeName(rel))
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" || rel == "." {
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
			"%w: %q under %s (expected %s or a nested %s/ within %d levels)",
			ErrNoCandidate, req.Name, req.Base, req.DirectPath, req.Name, req.MaxDepth,
		)
	case 1:
		return req.Candidates[0], nil, nil
	default:
		relCandidates := relativePaths(req.Base, req.Candidates)
		return "", relCandidates, fmt.Errorf(
			"%w: found %d %q directories under %s: %s",
			ErrAmbiguousCandidates, len(req.Candidates), req.Name, req.Base, strings.Join(relCandidates, ", "),
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
