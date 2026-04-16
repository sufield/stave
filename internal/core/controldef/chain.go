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
	Preconditions       []string           `yaml:"preconditions,omitempty"  json:"preconditions,omitempty"`
	Postconditions      []string           `yaml:"postconditions,omitempty" json:"postconditions,omitempty"`
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
	for _, cap := range c.Preconditions {
		if !IsValidCapability(cap) {
			return fmt.Errorf("chain %s: unknown precondition capability %q", c.ID, cap)
		}
	}
	for _, cap := range c.Postconditions {
		if !IsValidCapability(cap) {
			return fmt.Errorf("chain %s: unknown postcondition capability %q", c.ID, cap)
		}
	}
	return nil
}

// ValidCapabilities is the closed vocabulary of attack path capabilities.
var ValidCapabilities = map[string]bool{
	"internet_access":           true,
	"network_access_vpc":        true,
	"network_access_ec2":        true,
	"network_access_rds":        true,
	"network_access_eks":        true,
	"network_access_lambda":     true,
	"iam_credential_theft":      true,
	"aws_root_access":           true,
	"k8s_service_account_token": true,
	"db_credential_theft":       true,
	"secret_store_access":       true,
	"ec2_code_execution":        true,
	"container_code_execution":  true,
	"k8s_cluster_admin":         true,
	"s3_data_access":            true,
	"rds_data_access":           true,
	"cloudtrail_data_access":    true,
	"data_destruction":          true,
	"audit_trail_destroyed":     true,
}

// IsValidCapability returns true if the capability string is in the closed vocabulary.
func IsValidCapability(capability string) bool {
	return ValidCapabilities[capability]
}
