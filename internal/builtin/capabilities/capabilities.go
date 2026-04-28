// Package capabilities owns the closed vocabulary of attack-path
// capability strings that chains use in preconditions and
// postconditions. The vocabulary lives here (catalog layer) rather
// than in internal/core/ so that adding a capability for a new
// domain — AWS, M365, Cloudflare, EKS, GCP, Azure, GitHub, or
// anything else — never requires touching the engine.
//
// Adding a capability:
//  1. Append the string to builtinNames below.
//  2. Reference it from at least one chain YAML.
package capabilities

import (
	policy "github.com/sufield/stave/internal/core/controldef"
)

// builtinNames is the catalog's closed vocabulary of attack-path
// capabilities. Strings are sorted alphabetically for review-diff
// stability; the order has no runtime meaning.
var builtinNames = []string{
	"audit_trail_destroyed",
	"aws_root_access",
	"cdn_bypass_data_access",
	"cloudfront_origin_configured",
	"cloudtrail_data_access",
	"container_code_execution",
	"control_plane_code_execution",
	"data_access",
	"data_destruction",
	"data_in_transit_exposure",
	"data_warehouse_compromise",
	"database_compromise",
	"db_credential_theft",
	"domain_takeover",
	"ec2_code_execution",
	"encryption_bypass",
	"iam_credential_theft",
	"initial_access",
	"internet_access",
	"invisible_data_exfiltration",
	"k8s_cluster_admin",
	"k8s_service_account_token",
	"kms_encryption_configured",
	"kms_key_compromise",
	"network_access_ec2",
	"network_access_eks",
	"network_access_lambda",
	"network_access_rds",
	"network_access_vpc",
	"rds_data_access",
	"resource_policy_escalation",
	"s3_data_access",
	"s3_replication_configured",
	"scp_governance_configured",
	"secret_store_access",
	"service_disruption",
	"shadow_admin_access",
	"ungoverned_operation",
	"vpc_instance_compromise",
}

// Builtin returns the catalog's capability registry. Composition
// roots construct one of these once at startup and pass it to
// chain loaders and linters.
func Builtin() policy.CapabilityRegistry {
	set := make(policy.CapabilitySet, len(builtinNames))
	for _, name := range builtinNames {
		set[name] = struct{}{}
	}
	return set
}
