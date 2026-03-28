package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/kernel"
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
	if err := populatePlanHashes(plan, opts.Hasher); err != nil {
		return nil, fmt.Errorf("hash plan inputs: %w", err)
	}
	if err := populatePlanLockHash(plan, opts.ProjectRoot, opts.Hasher); err != nil {
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

func populatePlanHashes(plan *EvaluationPlan, hasher appcontracts.ContentHasher) error {
	if hasher == nil {
		return nil
	}
	// Skip controls directory hashing when the path doesn't exist on disk.
	// This happens when controls come from built-in packs (enabled_control_packs)
	// rather than from a local directory.
	if _, statErr := os.Stat(plan.ControlsPath); statErr == nil {
		h, err := hasher.HashDir(plan.ControlsPath, ".yaml", ".yml")
		if err != nil {
			return fmt.Errorf("controls directory %s: %w", plan.ControlsPath, err)
		}
		plan.ControlsHash = kernel.Digest(h)
	}

	if plan.ObservationsPath != "" {
		h, err := hasher.HashDir(plan.ObservationsPath, ".json")
		if err != nil {
			return fmt.Errorf("observations directory %s: %w", plan.ObservationsPath, err)
		}
		plan.ObservationsHash = kernel.Digest(h)
	}

	if plan.ConfigPath != "" {
		h, err := hasher.HashFile(plan.ConfigPath)
		if err != nil {
			return fmt.Errorf("config file %s: %w", plan.ConfigPath, err)
		}
		plan.ConfigHash = kernel.Digest(h)
	}
	return nil
}

// resolveLockPath returns the lock file path if a project root is set.
func resolveLockPath(projectRoot string) string {
	root := strings.TrimSpace(projectRoot)
	if root == "" {
		return ""
	}
	return filepath.Join(root, "stave.lock")
}

func populatePlanLockHash(plan *EvaluationPlan, projectRoot string, hasher appcontracts.ContentHasher) error {
	lockPath := resolveLockPath(projectRoot)
	if lockPath == "" || hasher == nil {
		return nil
	}
	h, err := hasher.HashFile(lockPath)
	if err != nil {
		// Lock file is optional — absence is not an error.
		return nil
	}
	plan.LockFile = lockPath
	plan.LockHash = kernel.Digest(h)
	return nil
}
