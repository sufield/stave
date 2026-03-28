package compose

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/adapters/gitinfo"
	"github.com/sufield/stave/internal/core/evaluation"
)

// AuditGitStatus gathers git metadata for specific paths.
// Best-effort: if baseDir is empty, falls back to os.Getwd(). If that also
// fails, returns nil (no git metadata). This is metadata for output enrichment,
// not a critical path — callers should always pass a resolved baseDir.
func AuditGitStatus(baseDir string, watchPaths []string) *evaluation.GitInfo {
	if strings.TrimSpace(baseDir) == "" {
		baseDir, _ = os.Getwd()
	}
	repoRoot, ok := gitinfo.DetectRepoRoot(baseDir)
	if !ok {
		return nil
	}
	head, headErr := gitinfo.HeadCommit(repoRoot)

	var cleaned []string
	for _, p := range watchPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(baseDir, p)
		}
		cleaned = append(cleaned, abs)
	}

	dirty, dirtyList, dirtyErr := gitinfo.IsDirty(repoRoot, cleaned)

	// Fail closed: if git commands error, report as dirty so outputs
	// don't falsely claim a clean repository state.
	if headErr != nil || dirtyErr != nil {
		dirty = true
	}

	return &evaluation.GitInfo{
		RepoRoot:  repoRoot,
		Head:      head,
		Dirty:     dirty,
		DirtyList: dirtyList,
	}
}

// WarnGitDirty logs a warning if the repository is dirty.
func WarnGitDirty(stderr io.Writer, git *evaluation.GitInfo, label string, quiet bool) {
	if git == nil || !git.Dirty || quiet {
		return
	}
	slog.Warn("uncommitted changes detected",
		"scope", label,
		"dirty_files", strings.Join(git.DirtyList, ", "))
}
