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
	"internet_access":              true,
	"network_access_vpc":           true,
	"network_access_ec2":           true,
	"network_access_rds":           true,
	"network_access_eks":           true,
	"network_access_lambda":        true,
	"iam_credential_theft":         true,
	"aws_root_access":              true,
	"k8s_service_account_token":    true,
	"db_credential_theft":          true,
	"secret_store_access":          true,
	"ec2_code_execution":           true,
	"container_code_execution":     true,
	"k8s_cluster_admin":            true,
	"s3_data_access":               true,
	"rds_data_access":              true,
	"cloudtrail_data_access":       true,
	"data_destruction":             true,
	"audit_trail_destroyed":        true,
	"cdn_bypass_data_access":       true,
	"data_access":                  true,
	"database_compromise":          true,
	"data_warehouse_compromise":    true,
	"invisible_data_exfiltration":  true,
	"vpc_instance_compromise":      true,
	"encryption_bypass":            true,
	"s3_replication_configured":    true,
	"kms_encryption_configured":    true,
	"cloudfront_origin_configured": true,
	"data_in_transit_exposure":     true,
	"scp_governance_configured":    true,
	"ungoverned_operation":         true,
	"kms_key_compromise":           true,
	"control_plane_code_execution": true,
	"resource_policy_escalation":   true,
	"shadow_admin_access":          true,
}

// IsValidCapability returns true if the capability string is in the closed vocabulary.
func IsValidCapability(capability string) bool {
	return ValidCapabilities[capability]
}

// ChainRefIssue records one chain that references controls missing
// from the catalog passed to [ValidateChainRefs]. Consumers format
// the list into user-facing warnings or errors.
type ChainRefIssue struct {
	ChainID        string
	MissingControl []kernel.ControlID
}

// ValidateChainRefs cross-checks every chain's control references
// against the provided catalog. The returned slice has one entry
// per chain that references at least one control not present in
// catalog; chains with all references present produce no entry.
//
// Callers decide whether the result is fatal (strict validation)
// or advisory (runtime profile filtering). The function itself
// makes no policy choice — it returns data.
func ValidateChainRefs(chains []ChainDefinition, catalog []ControlDefinition) []ChainRefIssue {
	if len(chains) == 0 {
		return nil
	}
	known := make(map[kernel.ControlID]struct{}, len(catalog))
	for i := range catalog {
		known[catalog[i].ID] = struct{}{}
	}
	var issues []ChainRefIssue
	for i := range chains {
		chain := &chains[i]
		var missing []kernel.ControlID
		for _, ref := range chain.ControlIDs {
			if _, ok := known[ref]; !ok {
				missing = append(missing, ref)
			}
		}
		if len(missing) > 0 {
			issues = append(issues, ChainRefIssue{
				ChainID:        chain.ID,
				MissingControl: missing,
			})
		}
	}
	return issues
}
