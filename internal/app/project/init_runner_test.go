package project

import (
	"errors"
	"testing"
)

func TestRunInit_Success(t *testing.T) {
	req := InitRequest{
		Dir:            "/tmp/project",
		Profile:        "default",
		CaptureCadence: "daily",
	}
	deps := InitDeps{
		ValidateInputs: func(rawDir, profile, cadence string) (string, error) {
			return "/tmp/project", nil
		},
		Plan: func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error) {
			return ScaffoldResult{}, nil
		},
		Scaffold: func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error) {
			return ScaffoldResult{
				Dirs:    []string{"controls", "observations"},
				Created: []string{"stave.yaml"},
			}, nil
		},
	}

	result, err := deps.run(t, req)
	if err != nil {
		t.Fatalf("RunInit error: %v", err)
	}
	if result.BaseDir != "/tmp/project" {
		t.Errorf("BaseDir = %q, want %q", result.BaseDir, "/tmp/project")
	}
	if len(result.Dirs) != 2 {
		t.Errorf("Dirs count = %d, want 2", len(result.Dirs))
	}
	if result.DryRun {
		t.Error("DryRun should be false")
	}
}

func TestRunInit_DryRun(t *testing.T) {
	planCalled := false
	scaffoldCalled := false

	req := InitRequest{
		Dir:    "/tmp/project",
		DryRun: true,
	}
	deps := InitDeps{
		ValidateInputs: func(rawDir, profile, cadence string) (string, error) {
			return "/tmp/project", nil
		},
		Plan: func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error) {
			planCalled = true
			return ScaffoldResult{Dirs: []string{"controls"}}, nil
		},
		Scaffold: func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error) {
			scaffoldCalled = true
			return ScaffoldResult{}, nil
		},
	}

	result, err := RunInit(req, deps)
	if err != nil {
		t.Fatalf("RunInit error: %v", err)
	}
	if !planCalled {
		t.Error("expected Plan to be called in dry-run mode")
	}
	if scaffoldCalled {
		t.Error("Scaffold should not be called in dry-run mode")
	}
	if !result.DryRun {
		t.Error("result.DryRun should be true")
	}
}

func TestRunInit_NilValidateInputs(t *testing.T) {
	deps := InitDeps{
		Plan:     func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold: func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
	}
	_, err := RunInit(InitRequest{}, deps)
	if err == nil {
		t.Fatal("expected error when ValidateInputs is nil")
	}
}

func TestRunInit_NilPlan(t *testing.T) {
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Scaffold:       func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
	}
	_, err := RunInit(InitRequest{}, deps)
	if err == nil {
		t.Fatal("expected error when Plan is nil")
	}
}

func TestRunInit_NilScaffold(t *testing.T) {
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Plan:           func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
	}
	_, err := RunInit(InitRequest{}, deps)
	if err == nil {
		t.Fatal("expected error when Scaffold is nil")
	}
}

func TestRunInit_ValidateInputsError(t *testing.T) {
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) {
			return "", errors.New("bad input")
		},
		Plan:     func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold: func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
	}
	_, err := RunInit(InitRequest{Dir: "x"}, deps)
	if err == nil {
		t.Fatal("expected error from ValidateInputs")
	}
}

func TestRunInit_ScaffoldError(t *testing.T) {
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Plan:           func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold: func(string, bool, ScaffoldOptions) (ScaffoldResult, error) {
			return ScaffoldResult{}, errors.New("scaffold failed")
		},
	}
	_, err := RunInit(InitRequest{Dir: "/tmp"}, deps)
	if err == nil {
		t.Fatal("expected error from Scaffold")
	}
}

func TestRunInit_AfterScaffold(t *testing.T) {
	afterCalled := false
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Plan:           func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold: func(string, bool, ScaffoldOptions) (ScaffoldResult, error) {
			return ScaffoldResult{}, nil
		},
		AfterScaffold: func(baseDir string) error {
			afterCalled = true
			if baseDir != "/tmp" {
				t.Errorf("AfterScaffold baseDir = %q, want %q", baseDir, "/tmp")
			}
			return nil
		},
	}
	_, err := RunInit(InitRequest{Dir: "/tmp"}, deps)
	if err != nil {
		t.Fatalf("RunInit error: %v", err)
	}
	if !afterCalled {
		t.Error("expected AfterScaffold to be called")
	}
}

func TestRunInit_AfterScaffoldError(t *testing.T) {
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Plan:           func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold:       func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		AfterScaffold:  func(string) error { return errors.New("after failed") },
	}
	_, err := RunInit(InitRequest{Dir: "/tmp"}, deps)
	if err == nil {
		t.Fatal("expected error from AfterScaffold")
	}
}

func TestRunInit_AfterScaffoldNotCalledInDryRun(t *testing.T) {
	afterCalled := false
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Plan:           func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold:       func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		AfterScaffold:  func(string) error { afterCalled = true; return nil },
	}
	_, err := RunInit(InitRequest{Dir: "/tmp", DryRun: true}, deps)
	if err != nil {
		t.Fatalf("RunInit error: %v", err)
	}
	if afterCalled {
		t.Error("AfterScaffold should not be called in dry-run mode")
	}
}

func TestRunInit_PassesOptions(t *testing.T) {
	var capturedOpts ScaffoldOptions
	deps := InitDeps{
		ValidateInputs: func(string, string, string) (string, error) { return "/tmp", nil },
		Plan:           func(string, bool, ScaffoldOptions) (ScaffoldResult, error) { return ScaffoldResult{}, nil },
		Scaffold: func(baseDir string, overwrite bool, opts ScaffoldOptions) (ScaffoldResult, error) {
			capturedOpts = opts
			return ScaffoldResult{}, nil
		},
	}
	req := InitRequest{
		Dir:               "/tmp",
		Profile:           "hipaa",
		WithGitHubActions: true,
		CaptureCadence:    "hourly",
		Force:             true,
	}
	_, err := RunInit(req, deps)
	if err != nil {
		t.Fatalf("RunInit error: %v", err)
	}
	if capturedOpts.Profile != "hipaa" {
		t.Errorf("Profile = %q, want %q", capturedOpts.Profile, "hipaa")
	}
	if !capturedOpts.WithGitHubActions {
		t.Error("WithGitHubActions should be true")
	}
	if capturedOpts.CaptureCadence != "hourly" {
		t.Errorf("CaptureCadence = %q, want %q", capturedOpts.CaptureCadence, "hourly")
	}
}

// helper to call RunInit.
func (d InitDeps) run(t *testing.T, req InitRequest) (InitResult, error) {
	t.Helper()
	return RunInit(req, d)
}
