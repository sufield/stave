package initcmd

import (
	"fmt"
	"io"
	"os"

	projectapp "github.com/sufield/stave/internal/app/project"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
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
func (r *InitRunner) Run(req *InitRequest) error {
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
			return scaffoldProject(baseDir, scaffoldWriteOpts{
				Overwrite: overwrite, AllowSymlink: r.AllowSymlink,
			}, scaffoldOptions{
				Profile:           opts.Profile,
				WithGitHubActions: opts.WithGitHubActions,
				CaptureCadence:    opts.CaptureCadence,
			})
		},
		AfterScaffold: func(baseDir string) error {
			return maybePromptAndInitGitRepo(baseDir, os.Stdin, r.Stdout)
		},
	})
	if err != nil {
		return err
	}

	w := r.Stdout
	if r.Quiet {
		w = io.Discard
	}
	printScaffoldSummary(w, r.Stderr, scaffoldSummaryRequest{
		BaseDir: result.BaseDir,
		Dirs:    result.Dirs,
		Created: result.Created,
		Skipped: result.Skipped,
		DryRun:  result.DryRun,
	})
	return nil
}

func validateScaffoldInputs(rawDir, profile, cadence string) (string, error) {
	dir := fsutil.CleanUserPath(rawDir)
	if dir == "" {
		return "", &ui.UserError{Err: fmt.Errorf("--dir cannot be empty")}
	}
	if profile != "" && profile != profileAWSS3 {
		return "", &ui.UserError{Err: fmt.Errorf("unsupported --profile %q (supported: aws-s3)", profile)}
	}
	if cadence != cadenceDaily && cadence != cadenceHourly {
		return "", &ui.UserError{Err: fmt.Errorf("unsupported --capture-cadence %q (supported: daily, hourly)", cadence)}
	}
	return dir, nil
}
