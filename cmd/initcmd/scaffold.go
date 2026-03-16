package initcmd

import (
	"context"
	"io"
	"os"

	projectapp "github.com/sufield/stave/internal/app/project"
)

// InitRequest defines the parameters for project initialization.
type InitRequest struct {
	Dir               string
	Profile           string
	DryRun            bool
	WithGitHubActions bool
	CaptureCadence    string
}

type scaffoldOptions struct {
	Profile           string
	WithGitHubActions bool
	CaptureCadence    string
}

// InitRunner orchestrates project scaffolding.
type InitRunner struct {
	Stdout       io.Writer
	Stderr       io.Writer
	Force        bool
	AllowSymlink bool
	Quiet        bool
}

// Run executes the project initialization workflow.
func (r *InitRunner) Run(_ context.Context, req *InitRequest) error {
	result, err := projectapp.RunInit(projectapp.InitRequest{
		Dir:               req.Dir,
		Profile:           req.Profile,
		DryRun:            req.DryRun,
		WithGitHubActions: req.WithGitHubActions,
		CaptureCadence:    req.CaptureCadence,
		Force:             r.Force,
	}, projectapp.InitDeps{
		ValidateInputs: validateScaffoldInputs,
		Plan: func(baseDir string, overwrite bool, opts projectapp.ScaffoldOptions) (projectapp.ScaffoldResult, error) {
			return scaffoldPlan(baseDir, overwrite, scaffoldOptions{
				Profile:           opts.Profile,
				WithGitHubActions: opts.WithGitHubActions,
				CaptureCadence:    opts.CaptureCadence,
			})
		},
		Scaffold: func(baseDir string, overwrite bool, opts projectapp.ScaffoldOptions) (projectapp.ScaffoldResult, error) {
			return scaffoldProject(baseDir, overwrite, scaffoldOptions{
				Profile:           opts.Profile,
				WithGitHubActions: opts.WithGitHubActions,
				CaptureCadence:    opts.CaptureCadence,
			}, r.AllowSymlink)
		},
		AfterScaffold: func(baseDir string) error {
			return maybePromptAndInitGitRepo(baseDir, os.Stdin, r.Stdout)
		},
	})
	if err != nil {
		return err
	}

	printScaffoldSummary(r.Stdout, scaffoldSummaryRequest{
		BaseDir: result.BaseDir,
		Dirs:    result.Dirs,
		Created: result.Created,
		Skipped: result.Skipped,
		DryRun:  result.DryRun,
	}, r.Quiet)
	return nil
}
