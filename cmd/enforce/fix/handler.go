package fix

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Request defines the parameters for a single-finding fix operation.
type Request struct {
	InputPath  string
	FindingRef string // Format: <control_id>@<asset_id>
	Stdout     io.Writer
}

// Runner orchestrates finding remediation and fix-loop workflows.
type Runner struct {
	Provider    *compose.Provider
	Clock       ports.Clock
	Planner     *remediation.Planner
	Sanitizer   kernel.Sanitizer
	FileOptions cmdutil.FileOptions
}

// NewRunner initializes a runner with required dependencies.
func NewRunner(p *compose.Provider, clock ports.Clock) *Runner {
	return &Runner{
		Provider: p,
		Clock:    clock,
		Planner:  remediation.NewPlanner(crypto.NewHasher()),
	}
}

// Run executes the fix plan generation workflow.
func (r *Runner) Run(ctx context.Context, req Request) error {
	needle := strings.TrimSpace(req.FindingRef)
	if needle == "" {
		return &ui.UserError{Err: fmt.Errorf("finding reference selector cannot be empty")}
	}

	findings, err := r.loadFindings(fsutil.CleanUserPath(req.InputPath))
	if err != nil {
		return err
	}

	selected, err := r.selectFinding(findings, needle)
	if err != nil {
		return err
	}

	if selected.RemediationPlan == nil {
		selected.RemediationPlan = r.Planner.PlanFor(selected)
	}

	return r.writeResult(req.Stdout, selected)
}

func (r *Runner) loadFindings(path string) ([]remediation.Finding, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("reading input file: %w", err)
	}
	findings, err := evaljson.ParseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parsing evaluation results: %w", err)
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings found in %s", path)
	}
	return findings, nil
}

func (r *Runner) selectFinding(findings []remediation.Finding, needle string) (remediation.Finding, error) {
	for i := range findings {
		if findingKey(findings[i]) == needle {
			return findings[i], nil
		}
	}

	keys := make([]string, 0, len(findings))
	for i := range findings {
		keys = append(keys, findingKey(findings[i]))
	}
	slices.Sort(keys)

	return remediation.Finding{}, &ui.UserError{Err: fmt.Errorf(
		"finding %q not found; available findings:\n  %s",
		needle,
		strings.Join(keys, "\n  "),
	)}
}

func (r *Runner) writeResult(w io.Writer, f remediation.Finding) error {
	var err error
	printf := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	printf("Finding:     %s\n", findingKey(f))
	printf("Control:     %s\n", f.ControlName)
	printf("Asset:       %s (%s)\n", f.AssetID, f.AssetType)

	action := strings.TrimSpace(f.RemediationSpec.Action)
	if action != "" {
		printf("Remediation: %s\n", action)
	}

	printf("Fix Plan:\n")
	if err != nil {
		return err
	}

	return jsonutil.WriteIndented(w, f.RemediationPlan)
}

// findingKey returns the canonical string selector for a finding.
func findingKey(f remediation.Finding) string {
	return fmt.Sprintf("%s@%s", f.ControlID, f.AssetID)
}
