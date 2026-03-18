package compose

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/adapters/gitinfo"
	"github.com/sufield/stave/internal/domain/evaluation"
)

// AuditGitStatus gathers git metadata for specific paths.
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

// WarnGitDirty prints a warning to stderr if the repository is dirty.
func WarnGitDirty(stderr io.Writer, git *evaluation.GitInfo, label string, quiet bool) {
	if git == nil || !git.Dirty || quiet {
		return
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	fmt.Fprintf(stderr, "WARN: Uncommitted changes detected in %s inputs (%s). This run may not reflect committed state.\n",
		label, strings.Join(git.DirtyList, ", "))
}
