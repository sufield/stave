package project

import "fmt"

// InitRequest captures the init command execution inputs.
type InitRequest struct {
	Dir               string
	Profile           string
	DryRun            bool
	WithGitHubActions bool
	CaptureCadence    string
	Force             bool
}

// ScaffoldOptions controls scaffold generation behavior.
type ScaffoldOptions struct {
	Profile           string
	WithGitHubActions bool
	CaptureCadence    string
}

// InitResult contains scaffold outputs for presentation.
type InitResult struct {
	BaseDir string
	Dirs    []string
	Created []string
	Skipped []string
	DryRun  bool
}

// ScaffoldResult holds the outputs from a scaffold or plan operation.
type ScaffoldResult struct {
	Dirs    []string
	Created []string
	Skipped []string
}

// InitDeps provides command-agnostic callbacks for filesystem and validation.
type InitDeps struct {
	ValidateInputs func(rawDir, profile, cadence string) (string, error)
	Plan           func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error)
	Scaffold       func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error)
	AfterScaffold  func(baseDir string) error
}

// RunInit orchestrates project scaffold generation for the CLI layer.
func RunInit(req InitRequest, deps InitDeps) (InitResult, error) {
	if deps.ValidateInputs == nil {
		return InitResult{}, fmt.Errorf("validate inputs dependency is required")
	}
	if deps.Plan == nil || deps.Scaffold == nil {
		return InitResult{}, fmt.Errorf("scaffold dependencies are required")
	}

	cleanDir, err := deps.ValidateInputs(req.Dir, req.Profile, req.CaptureCadence)
	if err != nil {
		return InitResult{}, err
	}

	opts := ScaffoldOptions{
		Profile:           req.Profile,
		WithGitHubActions: req.WithGitHubActions,
		CaptureCadence:    req.CaptureCadence,
	}

	var sr ScaffoldResult
	if req.DryRun {
		sr, err = deps.Plan(cleanDir, req.Force, opts)
	} else {
		sr, err = deps.Scaffold(cleanDir, req.Force, opts)
	}
	if err != nil {
		return InitResult{}, err
	}
	if !req.DryRun && deps.AfterScaffold != nil {
		if err := deps.AfterScaffold(cleanDir); err != nil {
			return InitResult{}, err
		}
	}

	return InitResult{
		BaseDir: cleanDir,
		Dirs:    sr.Dirs,
		Created: sr.Created,
		Skipped: sr.Skipped,
		DryRun:  req.DryRun,
	}, nil
}
