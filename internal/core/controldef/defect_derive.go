package controldef

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/core/predicate"
)

// deriveResult tracks both the clauses and whether all paths had labels.
type deriveResult struct {
	clauses []string
	ok      bool // false if any non-gate path lacked a label
}

// DeriveDefect generates a human-readable defect description from a
// control's predicate tree. Returns empty string when the predicate
// contains fields without labels in the property registry (accuracy
// over coverage — unlabeled paths produce no output).
func DeriveDefect(p *UnsafePredicate) string {
	if p == nil {
		return ""
	}
	dr := &deriveResult{ok: true}
	for i := range p.All {
		collectClauses(&p.All[i], dr)
	}
	for i := range p.Any {
		collectClauses(&p.Any[i], dr)
	}
	if !dr.ok || len(dr.clauses) == 0 {
		return ""
	}
	return strings.Join(dr.clauses, ". ") + "."
}

func collectClauses(r *PredicateRule, dr *deriveResult) {
	for i := range r.All {
		collectClauses(&r.All[i], dr)
	}
	for i := range r.Any {
		collectClauses(&r.Any[i], dr)
	}

	if r.Field.IsZero() {
		return
	}

	field := r.Field.String()
	clean := strings.TrimPrefix(field, "properties.")

	if isKindGate(clean, r.Op) {
		return
	}
	if clean == "type" {
		return
	}
	if !r.ValueFromParam.IsZero() {
		return
	}

	if clause, ok := specialClause(clean, r.Op, r.Value.Raw()); ok {
		dr.clauses = append(dr.clauses, clause)
		return
	}

	label := pathLabel(clean)
	if label == "" {
		dr.ok = false
		return
	}

	phrase := operatorPhrase(r.Op, r.Value.Raw())
	if phrase == "" {
		return
	}

	dr.clauses = append(dr.clauses, capitalize(label)+" "+phrase)
}

// specialClause returns a fully-formed defect line for predicate
// rules whose generic "<label> <phrase>" rendering would obscure the
// posture issue. The rules are exact (path, op, value) matches so the
// table doubles as a registry of "we said exactly this when this
// predicate fired" — easy to grep, easy to extend.
//
// Three policy-state rules that benefit from a custom phrasing:
//   - empty policy_json: the absence of a resource policy is itself
//     the defect; "policy json is empty" reads like a typo, the
//     fully-formed line names AWS implicit deny so the operator
//     understands why the bucket still works without a policy.
//   - policy_is_effectively_public=true and
//     policy_has_scoping_condition=false: distinct postures whose
//     remediation steps differ; collapsing both into a generic
//     "access control issue" line was the failure mode this
//     replaces.
func specialClause(path string, op predicate.Operator, value any) (string, bool) {
	if op != predicate.OpEq {
		return "", false
	}
	switch path {
	case "storage.policy_json":
		if s, ok := value.(string); ok && s == "" {
			return "Bucket has no explicit policy (relying on implicit deny)", true
		}
	case "storage.access.policy_is_effectively_public":
		if b, ok := value.(bool); ok && b {
			return "Bucket policy allows overly broad access (effectively public per AWS PolicyStatus)", true
		}
	case "storage.access.policy_has_scoping_condition":
		if b, ok := value.(bool); ok && !b {
			return "Bucket policy contains a non-narrow Allow without a scoping Condition", true
		}
	}
	return "", false
}

func isKindGate(path string, op predicate.Operator) bool {
	return strings.HasSuffix(path, ".kind") && op == predicate.OpEq
}

// --- Operator phrase mapping ---

func operatorPhrase(op predicate.Operator, value any) string {
	switch op {
	case predicate.OpEq:
		return eqPhrase(value)
	case predicate.OpNe:
		return nePhrase(value)
	case predicate.OpGt:
		return fmt.Sprintf("exceeds %v", value)
	case predicate.OpLt:
		return fmt.Sprintf("is below %v", value)
	case predicate.OpGte:
		return fmt.Sprintf("is at least %v", value)
	case predicate.OpLte:
		return fmt.Sprintf("is at most %v", value)
	case predicate.OpMissing:
		return "is missing from the observation data"
	case predicate.OpPresent:
		if b, ok := value.(bool); ok {
			if b {
				return "is present"
			}
			return "is absent"
		}
		if value != nil {
			return "is present"
		}
		return "is absent"
	case predicate.OpContains:
		return fmt.Sprintf("includes %v", value)
	case predicate.OpIn:
		return fmt.Sprintf("is one of %v", value)
	default:
		return ""
	}
}

func eqPhrase(value any) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "is enabled"
		}
		return "is not enabled"
	case string:
		if v == "" {
			return "is empty"
		}
		return "is set to " + strconv.Quote(v)
	default:
		return fmt.Sprintf("is set to %v", value)
	}
}

func nePhrase(value any) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "is not enabled"
		}
		return "is enabled"
	case string:
		return "is not " + strconv.Quote(v)
	default:
		return fmt.Sprintf("is not %v", value)
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	// Don't capitalize if first char is already upper (abbreviation).
	if s[0] >= 'A' && s[0] <= 'Z' {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// --- Property path → human-readable label ---

// Abbreviations expanded to domain terms.
var abbreviations = map[string]string{
	"ebs": "EBS", "mfa": "MFA", "acl": "ACL", "tls": "TLS",
	"ssl": "SSL", "vpc": "VPC", "iam": "IAM", "s3": "S3",
	"rds": "RDS", "ec2": "EC2", "kms": "KMS", "ssh": "SSH",
	"http": "HTTP", "https": "HTTPS", "snmp": "SNMP", "ip": "IP",
	"dns": "DNS", "cdn": "CDN", "ssm": "SSM", "pab": "PAB",
	"cors": "CORS", "oac": "OAC", "oidc": "OIDC", "scp": "SCP",
	"laps": "LAPS", "ntlm": "NTLM", "smb": "SMB", "phi": "PHI",
	"pii": "PII", "cidr": "CIDR", "dlq": "DLQ", "api": "API",
	"ecs": "ECS", "eks": "EKS", "ecr": "ECR", "waf": "WAF",
	"mrap": "MRAP", "imdsv2": "IMDSv2", "sg": "SG", "ou": "OU",
	"fgac": "FGAC", "pitr": "PITR", "asg": "ASG", "rbac": "RBAC",
	"cwlogs": "CloudWatch Logs", "vds": "VDS",
}

// Boolean-state suffixes stripped when followed by the operator phrase.
var boolSuffixes = map[string]struct{}{
	"enabled": {}, "disabled": {}, "active": {},
	"configured": {}, "attached": {}, "encrypted": {},
	"blocked": {}, "required": {}, "managed": {},
}

// pathOverrides provides hand-tuned labels for paths where the
// algorithmic transform reads poorly.
var pathOverrides = map[string]string{ //nolint:gosec // property labels, not credentials
	"identity.policies.has_admin_access":                           "administrative access policy",
	"identity.policies.has_self_modify":                            "self-modification permissions",
	"identity.policies.has_direct_policies":                        "directly-attached managed policies",
	"identity.policies.has_inline_policies":                        "inline policies",
	"identity.policies.assumerole_unrestricted":                    "unrestricted AssumeRole permission",
	"identity.policies.passrole_unrestricted":                      "unrestricted PassRole permission",
	"identity.policies.passrole_has_service_condition":             "PassRole iam:PassedToService condition",
	"identity.trust_policy.has_cross_account_trust":                "cross-account trust",
	"identity.trust_policy.has_assumption_constraints":             "trust policy session-limiting conditions",
	"monitoring.metric_filters.iam_escalation_events.exists":       "IAM escalation event monitoring",
	"monitoring.metric_filters.cross_account_assume_role.exists":   "cross-account AssumeRole monitoring",
	"database.network.has_broad_sg_ingress":                        "database security group broad ingress",
	"container.task_role.is_shared":                                "task role sharing",
	"container.execution_role.is_overprivileged":                   "execution role permissions",
	"container_registry.policy.has_broad_cross_account":            "ECR repository cross-account policy",
	"container.image.from_trusted_registry":                        "container image registry trust",
	"container.network.in_public_subnet":                           "container public subnet placement",
	"threat_detection.ecs_runtime_monitoring.enabled":              "GuardDuty ECS Runtime Monitoring",
	"container.security.has_dangerous_capabilities":                "dangerous Linux capabilities",
	"container.image.is_digest_pinned":                             "container image digest pinning",
	"monitoring.metric_filters.lambda_error_alarms.exists":         "Lambda error alarm monitoring",
	"compute.vpc.uses_vpc_endpoints":                               "VPC endpoint usage for AWS services",
	"compute.vpc.in_vpc":                                           "VPC attachment",
	"compute.layers.has_embedded_secrets":                          "embedded secrets in Lambda layers",
	"cdn.origin.has_access_control":                                "CloudFront origin access control",
	"identity.trust_policy.has_org_id_condition":                   "aws:PrincipalOrgID trust condition",
	"identity.trust_policy.has_wildcard_principal":                 "wildcard principal in trust policy",
	"identity.policies.cloudshell_unrestricted":                    "unrestricted CloudShell access",
	"identity.policies.statement_count":                            "policy statement count",
	"identity.policies.service_wildcards_granted":                  "service-wildcard grants",
	"identity.console_password.disabled":                           "console password",
	"identity.console_access.mfa_enabled":                          "console MFA",
	"identity.credentials.has_expiry":                              "credential expiry",
	"identity.credentials.unused":                                  "credential usage",
	"identity.credentials.unused_days":                             "credential idle days",
	"identity.access_keys.has_stale_key":                           "access key age",
	"identity.access_keys.active_count":                            "active access key count",
	"identity.access_keys.created_at_setup":                        "setup-time access key",
	"identity.root.mfa_enabled":                                    "root account MFA",
	"identity.root.has_access_keys":                                "root account access keys",
	"identity.root.recent_usage":                                   "root account usage",
	"identity.root.api_activity_count":                             "root API activity",
	"identity.password_policy.require_uppercase":                   "password uppercase requirement",
	"identity.password_policy.require_lowercase":                   "password lowercase requirement",
	"identity.password_policy.require_numbers":                     "password number requirement",
	"identity.password_policy.require_symbols":                     "password symbol requirement",
	"identity.password_policy.min_length":                          "password minimum length",
	"identity.password_policy.password_reuse_prevention":           "password reuse prevention count",
	"identity.password_policy.password_last_changed_stale":         "password rotation status",
	"identity.role.has_data_and_iam_access":                        "data-plus-IAM separation of duties",
	"identity.role.elevated_since_days":                            "break-glass elevation duration",
	"identity.role.cross_account_trust_without_external_id":        "cross-account trust external ID",
	"identity.trust.oidc.has_oidc_trust":                           "OIDC federation trust",
	"identity.trust.oidc.subject_scoped":                           "OIDC subject scope",
	"identity.trust.oidc.subject_wildcard":                         "OIDC subject wildcard",
	"identity.trust.oidc.permissions_scoped":                       "OIDC role permissions scope",
	"identity.trust.service_principal_without_source_condition":    "service principal source condition",
	"identity.trust.confused_deputy_vulnerable":                    "confused deputy protection",
	"identity.vendor_trust.is_external_vendor":                     "external vendor trust",
	"identity.vendor_trust.dormant_days":                           "vendor trust dormancy",
	"identity.vendor_trust.has_overprivileged_access":              "vendor access scope",
	"identity.auth.mfa_enforced":                                   "MFA enforcement",
	"identity.tags.role-type":                                      "role purpose tag",
	"identity.entropy.category_mix_incompatible":                   "permission category compatibility",
	"identity.entropy.permission_drift_detected":                   "permission drift",
	"identity.entropy.intent_mismatch":                             "role intent mismatch",
	"identity.entropy.data_complete":                               "entitlement assessment data",
	"identity.blast_radius.reachable_resources":                    "reachable resource count",
	"identity.blast_radius.sensitive_resources":                    "reachable sensitive resource count",
	"identity.blast_radius.chain_depth":                            "role assumption chain depth",
	"identity.blast_radius.cross_account_without_external_id":      "cross-account blast radius external ID",
	"identity.account.inactive_days":                               "account inactive days",
	"identity.admin.count":                                         "administrator count",
	"identity.analyzer.access_analyzer_enabled":                    "IAM Access Analyzer",
	"identity.analyzer.unused_access_monitoring":                   "unused access monitoring",
	"identity.boundary.permissions_boundary_set":                   "permissions boundary",
	"identity.crosscloud.admin_access":                             "cross-cloud admin access",
	"identity.crosscloud.mfa_enforced":                             "cross-cloud MFA",
	"identity.cross_env.production_access_from_dev":                "cross-environment production access",
	"identity.cross_env.path_exists":                               "cross-environment access path",
	"identity.hardware_mfa.enabled":                                "hardware MFA token",
	"identity.federation.idp_configured":                           "identity federation",
	"identity.support.access_level":                                "support access level",
	"identity.list.restrict_ec2_describe":                          "EC2 describe restriction",
	"identity.incomplete.data_present":                             "IAM assessment data",
	"identity.zt.perimeter_only":                                   "network-perimeter-only access control",
	"identity.zt.short_lived_credentials":                          "short-lived credentials",
	"storage.controls.account_public_access_fully_blocked":         "account-level S3 Public Access Block",
	"storage.controls.public_access_block.block_public_acls":       "S3 BlockPublicAcls setting",
	"storage.controls.public_access_block.block_public_policy":     "S3 BlockPublicPolicy setting",
	"storage.controls.public_access_block.ignore_public_acls":      "S3 IgnorePublicAcls setting",
	"storage.controls.public_access_block.restrict_public_buckets": "S3 RestrictPublicBuckets setting",
	"storage.object_ownership.rule":                                "object ownership rule",
	"storage.macie.enabled":                                        "Macie data discovery",
	"storage.logging_destination.lifecycle_expiration_days":        "log lifecycle expiration",
	"storage.access.policy_disclosure":                             "bucket policy disclosure",
	"storage.access.policy_object_scoped":                          "object-scoped policy grant",
	"storage.access_grants.instance_exists":                        "S3 Access Grants instance",
	"storage.access_grants.account_filter":                         "Access Grants account filter",
	"storage.tags.public_list_intended":                            "public-list-intended tag",
	"storage.tags.cors_wildcard_intended":                          "CORS-wildcard-intended tag",
	"storage.tags.compliance":                                      "compliance tag",
	"storage.cors.wildcard_origin":                                 "CORS wildcard origin",
	"storage.access.public_read":                                   "public read access",
	"storage.access.public_list":                                   "public list access",
	"storage.access.public_write":                                  "public write access",
	"storage.access.acl_public_read":                               "ACL public read grant",
	"storage.access.acl_public_write":                              "ACL public write grant",
	"storage.access.policy_is_effectively_public":                  "effective public access via policy",
	"storage.access.policy_has_scoping_condition":                  "policy scoping condition",
	"storage.access.authenticated_read":                            "authenticated-users read access",
	"storage.access.authenticated_write":                           "authenticated-users write access",
	"storage.controls.public_access_fully_blocked":                 "S3 Public Access Block",
	"storage.encryption.enabled":                                   "server-side encryption",
	"storage.encryption.algorithm":                                 "encryption algorithm",
	"storage.versioning.enabled":                                   "versioning",
	"storage.versioning.mfa_delete_enabled":                        "MFA delete",
	"storage.logging.enabled":                                      "access logging",
	"storage.object_lock.enabled":                                  "object lock",
	"storage.replication.enabled":                                  "cross-region replication",
	"storage.tags.data-classification":                             "data classification tag",
	"compute.encryption.ebs_encrypted":                             "EBS volume encryption",
	"compute.ebs_encryption_by_default":                            "EBS default encryption",
	"compute.encrypted":                                            "snapshot encryption",
	"compute.is_public":                                            "public sharing",
	"compute.network.has_public_ip":                                "public IP address",
	"compute.network.imdsv2_required":                              "IMDSv2 enforcement",
	"compute.network.is_default_vpc":                               "default VPC deployment",
	"compute.network.imds_hop_limit":                               "IMDS hop limit",
	"compute.containers.present":                                   "container workloads",
	"compute.containers.has_host_network":                          "host-network containers",
	"compute.containers.has_bridge_network":                        "bridge-network containers",
	"compute.ssm_managed":                                          "SSM management",
	"compute.disable_api_termination":                              "termination protection",
	"compute.monitoring.detailed_enabled":                          "detailed monitoring",
	"compute.iam_instance_profile.attached":                        "IAM instance profile",
	"compute.iam_profile_attached":                                 "IAM instance role",
	"compute.user_data.has_embedded_credentials":                   "embedded credentials in user data",
	"compute.user_data.has_secrets":                                "secrets in user data",
	"compute.ami.is_deprecated_or_aged":                            "AMI currency",
	"compute.uses_launch_template":                                 "launch template usage",
	"compute.health_check_type":                                    "ASG health check type",
	"compute.is_default":                                           "default security group",
	"compute.rules_empty":                                          "security group rules",
	"compute.inbound_rules.broad_cidr_non_http":                    "broad CIDR on non-HTTP ports",
	"compute.inbound_rules.high_risk_ports_unrestricted":           "unrestricted high-risk ports",
	"network.map_public_ip_on_launch":                              "automatic public IP assignment",
	"network.has_restrictive_policy":                               "VPC endpoint policy",
	"network.flow_log.enabled":                                     "VPC flow logging",
	"iam.has_broad_ec2_describe":                                   "broad EC2 describe permissions",
	"ssm.session_manager.logging_enabled":                          "SSM session logging",
	"database.encryption.storage_encrypted":                        "database encryption at rest",
	"database.public_access":                                       "database public accessibility",
	"database.auto_minor_version_upgrade":                          "automatic minor version upgrade",
	"database.deletion_protection":                                 "deletion protection",
	"scp.production_ou_missing_restrictive_scp":                    "production OU SCP coverage",
	"scp.has_dangerous_allows":                                     "SCP dangerous allow statements",
	"scp.only_full_access":                                         "SCP-only-FullAWSAccess reliance",
	"scp.missing_create_restriction":                               "SCP identity creation restriction",
	"identity.scp.has_invalid_actions":                             "SCP invalid action references",
}

var arrayIndexRegex = regexp.MustCompile(`\[\d*\]`)

// pathLabel returns a human-readable label for a property path.
// Returns empty string for paths with no known label (the derivation
// suppresses output rather than showing raw schema paths).
func pathLabel(path string) string {
	if label, ok := pathOverrides[path]; ok {
		return label
	}
	return algorithmicLabel(path)
}

func algorithmicLabel(path string) string {
	// Strip namespace (first segment).
	_, rest, ok := strings.Cut(path, ".")
	if !ok {
		return ""
	}

	// Remove array indices.
	rest = arrayIndexRegex.ReplaceAllString(rest, "")

	// Split on dots and underscores.
	segments := strings.FieldsFunc(rest, func(r rune) bool {
		return r == '.' || r == '_'
	})
	if len(segments) == 0 {
		return ""
	}

	// Drop "has" prefix.
	if segments[0] == "has" {
		segments = segments[1:]
	}

	// Check if last segment is a boolean suffix — remember but don't
	// strip yet (we strip only when expanding).
	lastIsBool := false
	if len(segments) > 1 {
		_, lastIsBool = boolSuffixes[segments[len(segments)-1]]
	}

	// Expand abbreviations.
	expanded := make([]string, len(segments))
	for i, s := range segments {
		if exp, ok := abbreviations[strings.ToLower(s)]; ok {
			expanded[i] = exp
		} else {
			expanded[i] = s
		}
	}

	// Strip trailing boolean suffix (the operator phrase will convey state).
	if lastIsBool && len(expanded) > 1 {
		expanded = expanded[:len(expanded)-1]
	}

	label := strings.Join(expanded, " ")
	if label == "" {
		return ""
	}
	return label
}
