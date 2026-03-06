package project

import "fmt"

// EnforceRunRequest captures normalized enforce command input.
type EnforceRunRequest struct {
	InputPath string
	OutDir    string
	Mode      string
	DryRun    bool
}

// EnforceResult is the normalized enforce command output envelope.
type EnforceResult struct {
	SchemaVersion string
	Kind          string
	Mode          string
	OutputFile    string
	Targets       []string
}

// EnforcePlan carries renderable output plus result metadata.
type EnforcePlan struct {
	Result   EnforceResult
	Rendered string
}

// EnforceDeps provides adapter callbacks for command-layer side effects.
type EnforceDeps struct {
	ResolveRequest func() (EnforceRunRequest, error)
	BuildPlan      func(EnforceRunRequest) (EnforcePlan, error)
	WriteDryRun    func(EnforceResult) error
	WriteOutput    func(path, rendered string) error
	WriteResult    func(EnforceResult) error
}

// RunEnforce orchestrates enforce execution using injected callbacks.
func RunEnforce(deps EnforceDeps) error {
	if deps.ResolveRequest == nil || deps.BuildPlan == nil || deps.WriteDryRun == nil || deps.WriteOutput == nil || deps.WriteResult == nil {
		return fmt.Errorf("enforce dependencies are required")
	}

	req, err := deps.ResolveRequest()
	if err != nil {
		return fmt.Errorf("resolve request: %w", err)
	}
	plan, err := deps.BuildPlan(req)
	if err != nil {
		return fmt.Errorf("build plan: %w", err)
	}
	if req.DryRun {
		return deps.WriteDryRun(plan.Result)
	}
	if err := deps.WriteOutput(plan.Result.OutputFile, plan.Rendered); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := deps.WriteResult(plan.Result); err != nil {
		return fmt.Errorf("write result: %w", err)
	}
	return nil
}
