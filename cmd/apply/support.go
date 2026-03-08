package apply

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	exemptionyaml "github.com/sufield/stave/internal/adapters/input/exemption/yaml"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// attachRunIDFromPlan derives a run ID from the evaluation plan and sets it on
// the default logger.
func attachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	if plan == nil {
		return
	}
	attachRunID(strings.TrimSpace(plan.ObservationsHash.String()), strings.TrimSpace(plan.ControlsHash.String()))
}

// attachRunID computes a run ID from input hashes and sets it on the default logger.
func attachRunID(inputsHash, controlsHash string) {
	cmdutil.AttachRunID(inputsHash, controlsHash)
}

func resolveApplyContextName(projectRoot string) string {
	if sc, err := cmdutil.ResolveSelectedGlobalContext(); err == nil && sc.Active && strings.TrimSpace(sc.Name) != "" {
		return strings.TrimSpace(sc.Name)
	}
	base := filepath.Base(projectRoot)
	if strings.TrimSpace(base) == "" || base == "." || base == string(os.PathSeparator) {
		return "default"
	}
	return base
}

func findProjectConfig() (*cmdutil.ProjectConfig, bool) {
	return cmdutil.FindProjectConfig()
}

func findProjectConfigWithPath() (*cmdutil.ProjectConfig, string, bool) {
	return cmdutil.FindProjectConfigWithPath()
}

func findUserConfigWithPath() (*cmdutil.UserConfig, string, bool) {
	return cmdutil.FindUserConfigWithPath()
}

func collectGitAudit(baseDir string, watchPaths []string) *evaluation.GitInfo {
	return cmdutil.CollectGitAudit(baseDir, watchPaths)
}

func newObservationRepository() (appcontracts.ObservationRepository, error) {
	return cmdutil.NewObservationRepository()
}

func newStdinObservationRepository(r io.Reader) (appcontracts.ObservationRepository, error) {
	return cmdutil.NewStdinObservationRepository(r)
}

func newControlRepository() (appcontracts.ControlRepository, error) {
	return cmdutil.NewControlRepository()
}

func rootForContextName() string { return cmdutil.RootForContextName() }

func inferControlsDir(cmd *cobra.Command, current string) string {
	return cmdutil.InferControlsDir(cmd, current)
}

func inferObservationsDir(cmd *cobra.Command, current string) string {
	return cmdutil.InferObservationsDir(cmd, current)
}

func resetInferAttempts() { cmdutil.ResetInferAttempts() }

func explainInferenceFailure(name string) string {
	return cmdutil.ExplainInferenceFailure(name)
}

func loadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg, err := exemptionyaml.LoadExemptionConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load ignore file: %w", err)
	}
	return cfg, nil
}

// warnIfGitDirty prints a warning if git is dirty and quiet mode is not enabled.
func warnIfGitDirty(cmd *cobra.Command, git *evaluation.GitInfo, label string) {
	if git == nil || !git.Dirty {
		return
	}
	if cmdutil.QuietEnabled(cmd) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "WARN: Uncommitted changes detected in %s inputs (%s). This run may not reflect committed state.\n", label, strings.Join(git.DirtyList, ", "))
}

// toControlIDs converts a string slice to kernel.ControlID slice.
func toControlIDs(raw []string) []kernel.ControlID {
	out := make([]kernel.ControlID, 0, len(raw))
	for _, s := range raw {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, kernel.ControlID(trimmed))
		}
	}
	return out
}
