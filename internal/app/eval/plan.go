package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// EvaluationPlan holds resolved paths and content hashes for an evaluation run.
type EvaluationPlan struct {
	ContextName      string        `json:"context_name"`
	ProjectRoot      string        `json:"-"`
	ControlsPath     string        `json:"controls_path"`
	ControlsHash     kernel.Digest `json:"controls_hash,omitempty"`
	ObservationsPath string        `json:"observations_path"`
	ObservationsHash kernel.Digest `json:"observations_hash,omitempty"`
	ConfigPath       string        `json:"config_path,omitempty"`
	ConfigHash       kernel.Digest `json:"config_hash,omitempty"`
	UserConfigPath   string        `json:"user_config_path,omitempty"`
	LockFile         string        `json:"lock_file,omitempty"`
	LockHash         kernel.Digest `json:"lock_hash,omitempty"`
}

// NewPlan resolves paths and calculates content hashes for the evaluation plan.
func NewPlan(opts Options) (*EvaluationPlan, error) {
	plan := &EvaluationPlan{
		ContextName:      opts.resolveContextName(),
		ProjectRoot:      strings.TrimSpace(opts.ProjectRoot),
		ControlsPath:     opts.ControlsDir,
		ObservationsPath: opts.ObservationsSource.Path(),
	}
	populatePlanConfigPaths(plan, opts)
	if err := populatePlanHashes(plan); err != nil {
		return nil, fmt.Errorf("hash plan inputs: %w", err)
	}
	if err := populatePlanLockHash(plan, opts.ProjectRoot); err != nil {
		return nil, fmt.Errorf("hash lock file: %w", err)
	}
	return plan, nil
}

func populatePlanConfigPaths(plan *EvaluationPlan, opts Options) {
	if cfgPath, ok := opts.FindConfigPath(); ok {
		plan.ConfigPath = cfgPath
	}
	if userPath, ok := opts.FindUserConfigPath(); ok {
		plan.UserConfigPath = userPath
	}
}

func populatePlanHashes(plan *EvaluationPlan) error {
	h, err := fsutil.HashDirByExt(plan.ControlsPath, ".yaml", ".yml")
	if err != nil {
		return fmt.Errorf("controls directory %s: %w", plan.ControlsPath, err)
	}
	plan.ControlsHash = h

	if plan.ObservationsPath != "" {
		h, err = fsutil.HashDirByExt(plan.ObservationsPath, ".json")
		if err != nil {
			return fmt.Errorf("observations directory %s: %w", plan.ObservationsPath, err)
		}
		plan.ObservationsHash = h
	}

	if plan.ConfigPath != "" {
		h, err = fsutil.HashFile(plan.ConfigPath)
		if err != nil {
			return fmt.Errorf("config file %s: %w", plan.ConfigPath, err)
		}
		plan.ConfigHash = h
	}
	return nil
}

func populatePlanLockHash(plan *EvaluationPlan, projectRoot string) error {
	root := strings.TrimSpace(projectRoot)
	if root == "" {
		return nil
	}
	lockPath := filepath.Join(root, "stave.lock")
	if _, err := os.Stat(lockPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("lock file %s: %w", lockPath, err)
	}
	plan.LockFile = lockPath
	h, err := fsutil.HashFile(lockPath)
	if err != nil {
		return fmt.Errorf("lock file %s: %w", lockPath, err)
	}
	plan.LockHash = h
	return nil
}
