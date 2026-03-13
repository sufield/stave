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

// Request defines the parameters for a single finding fix plan.
type Request struct {
	InputPath  string
	FindingRef string
	Stdout     io.Writer
}

// Runner handles finding remediation and fix-loop orchestration.
type Runner struct {
	Provider    *compose.Provider
	Clock       ports.Clock
	Sanitizer   kernel.Sanitizer
	FileOptions cmdutil.FileOptions
}

// NewRunner initializes a runner with required dependencies.
func NewRunner(p *compose.Provider, clock ports.Clock) *Runner {
	return &Runner{
		Provider: p,
		Clock:    clock,
	}
}

// Fix generates a machine-readable fix plan for a specific finding.
func (r *Runner) Fix(_ context.Context, req Request) error {
	inputPath := fsutil.CleanUserPath(req.InputPath)
	findings, err := loadFixFindings(inputPath)
	if err != nil {
		return err
	}
	needle := strings.TrimSpace(req.FindingRef)
	if needle == "" {
		return &ui.UserError{Err: fmt.Errorf("--finding cannot be empty")}
	}
	selected, err := selectFixFinding(findings, needle)
	if err != nil {
		return err
	}
	selected = withRemediationPlan(selected)
	return writeFixResult(req.Stdout, selected)
}

func loadFixFindings(inputPath string) ([]remediation.Finding, error) {
	data, err := fsutil.ReadFileLimited(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read --input: %w", err)
	}
	findings, err := evaljson.ParseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parse evaluation: %w", err)
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings in %s", inputPath)
	}
	return findings, nil
}

func selectFixFinding(findings []remediation.Finding, needle string) (remediation.Finding, error) {
	for i := range findings {
		if fixFindingKey(findings[i]) == needle {
			return findings[i], nil
		}
	}
	keys := availableFindingKeys(findings)
	return remediation.Finding{}, fmt.Errorf(
		"finding %q not found; available finding IDs:\n%s",
		needle,
		strings.Join(keys, "\n"),
	)
}

func availableFindingKeys(findings []remediation.Finding) []string {
	keys := make([]string, 0, len(findings))
	for i := range findings {
		keys = append(keys, fixFindingKey(findings[i]))
	}
	slices.Sort(keys)
	return keys
}

func withRemediationPlan(selected remediation.Finding) remediation.Finding {
	if selected.RemediationPlan != nil {
		return selected
	}
	selected.RemediationPlan = remediation.NewPlanner(crypto.NewHasher()).PlanFor(selected)
	return selected
}

func writeFixResult(w io.Writer, selected remediation.Finding) error {
	if _, err := fmt.Fprintf(w, "Finding: %s\n", fixFindingKey(selected)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Control: %s\n", selected.ControlName); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Asset: %s (%s)\n", selected.AssetID, selected.AssetType); err != nil {
		return err
	}
	remediationAction := strings.TrimSpace(selected.RemediationSpec.Action)
	if remediationAction != "" {
		if _, err := fmt.Fprintf(w, "Remediation: %s\n", remediationAction); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, "Fix Plan:"); err != nil {
		return err
	}
	return jsonutil.WriteIndented(w, selected.RemediationPlan)
}

func fixFindingKey(f remediation.Finding) string {
	return fmt.Sprintf("%s@%s", f.ControlID, f.AssetID)
}
