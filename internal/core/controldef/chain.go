package controldef

import (
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/core/kernel"
)

// ChainDefinition describes a safety chain — a set of controls whose
// co-failure creates a compound risk greater than the sum of individual
// findings. When the number of failing controls meets the escalation
// threshold, the chain engine emits a compound finding.
type ChainDefinition struct {
	ID                  string             `yaml:"id"                  json:"id"`
	Description         string             `yaml:"description"         json:"description"`
	ControlIDs          []kernel.ControlID `yaml:"controls"            json:"controls"`
	EscalationThreshold int                `yaml:"escalation_threshold" json:"escalation_threshold"`
	CompoundSeverity    Severity           `yaml:"compound_severity"   json:"compound_severity"`
}

// Validate checks that the chain definition has all required fields.
func (c *ChainDefinition) Validate() error {
	if c.ID == "" {
		return errors.New("chain: missing id")
	}
	if len(c.ControlIDs) < 2 {
		return fmt.Errorf("chain %s: requires at least 2 controls", c.ID)
	}
	if c.EscalationThreshold < 1 {
		return fmt.Errorf("chain %s: escalation_threshold must be >= 1", c.ID)
	}
	if c.EscalationThreshold > len(c.ControlIDs) {
		return fmt.Errorf("chain %s: escalation_threshold (%d) > control count (%d)",
			c.ID, c.EscalationThreshold, len(c.ControlIDs))
	}
	return nil
}
