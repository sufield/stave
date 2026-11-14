package eval

import (
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
