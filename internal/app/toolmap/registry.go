// Package toolmap maps offensive security tools to the AWS
// configuration prerequisites they need to succeed, using the
// attack path capability vocabulary from attackpath.Build.
package toolmap

// Tool describes an offensive security tool and the
// capabilities it requires to operate.
type Tool struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Reference     string         `json:"reference"`
	Prerequisites []Prerequisite `json:"prerequisites"`
}

// Prerequisite is a (capability, field path) pair describing
// what AWS configuration state a tool needs.
type Prerequisite struct {
	Capability string `json:"capability"`
	FieldPath  string `json:"field_path"`
	Rationale  string `json:"rationale"`
}

// Registry holds the known tool → prerequisite mappings.
type Registry struct {
	tools map[string]Tool
}

// NewRegistry returns a registry populated with the built-in tools.
func NewRegistry() *Registry {
	r := &Registry{tools: make(map[string]Tool, len(builtinTools))}
	for _, t := range builtinTools {
		r.tools[t.Name] = t
	}
	return r
}

// Tool returns a tool by name.
func (r *Registry) Tool(name string) (Tool, bool) {
	if r == nil {
		return Tool{}, false
	}
	t, ok := r.tools[name]
	return t, ok
}

// All returns every registered tool, sorted by name.
func (r *Registry) All() []Tool {
	if r == nil {
		return nil
	}
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sortTools(out)
	return out
}

// ToolsForCapability returns all tools whose prerequisites include
// the given capability token.
func (r *Registry) ToolsForCapability(capability string) []Tool {
	if r == nil {
		return nil
	}
	var out []Tool
	for _, t := range r.tools {
		for _, p := range t.Prerequisites {
			if p.Capability == capability {
				out = append(out, t)
				break
			}
		}
	}
	sortTools(out)
	return out
}

// CapabilitiesForTool returns the set of capability tokens a
// tool requires.
func (r *Registry) CapabilitiesForTool(name string) []string {
	t, ok := r.tools[name]
	if !ok {
		return nil
	}
	seen := make(map[string]struct{}, len(t.Prerequisites))
	var caps []string
	for _, p := range t.Prerequisites {
		if _, dup := seen[p.Capability]; !dup {
			seen[p.Capability] = struct{}{}
			caps = append(caps, p.Capability)
		}
	}
	return caps
}

var builtinTools = []Tool{
	{
		Name:        "pacu",
		Description: "AWS exploitation framework — IAM escalation, credential harvesting, persistence",
		Reference:   "https://github.com/RhinoSecurityLabs/pacu",
		Prerequisites: []Prerequisite{
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.has_admin_access", Rationale: "iam__privesc_scan enumerates escalation paths from over-permissioned roles"},
			{Capability: "ec2_code_execution", FieldPath: "properties.compute.imds.version", Rationale: "ec2__steal_ec2_metadata targets IMDSv1 for credential theft"},
			{Capability: "s3_data_access", FieldPath: "properties.storage.access.public_read", Rationale: "s3__download_bucket exfiltrates from readable buckets"},
		},
	},
	{
		Name:        "stratus-red-team",
		Description: "Granular cloud attack technique detonation mapped to MITRE ATT&CK",
		Reference:   "https://github.com/DataDog/stratus-red-team",
		Prerequisites: []Prerequisite{
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.credential.access_key_age_days", Rationale: "aws.credential-access.ec2-steal-instance-credentials needs stale long-term keys"},
			{Capability: "ec2_code_execution", FieldPath: "properties.compute.security_group.ingress_unrestricted", Rationale: "aws.initial-access.console-login-without-mfa targets exposed instances"},
			{Capability: "audit_trail_destroyed", FieldPath: "properties.audit.kind", Rationale: "aws.defense-evasion.cloudtrail-stop disables audit logging"},
		},
	},
	{
		Name:        "cloudfox",
		Description: "AWS attack surface enumeration — finds exploitable services, roles, and data paths",
		Reference:   "https://github.com/BishopFox/cloudfox",
		Prerequisites: []Prerequisite{
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.escalation", Rationale: "permissions command maps IAM escalation graph"},
			{Capability: "secret_store_access", FieldPath: "properties.secret.access.rotation_enabled", Rationale: "secrets command enumerates accessible secrets"},
			{Capability: "network_access_ec2", FieldPath: "properties.compute.network.auto_assign_public_ip", Rationale: "instances command finds publicly reachable EC2"},
		},
	},
	{
		Name:        "prowler",
		Description: "AWS CIS/NIST security assessment — used as a comparison baseline",
		Reference:   "https://github.com/prowler-cloud/prowler",
		Prerequisites: []Prerequisite{
			{Capability: "s3_data_access", FieldPath: "properties.storage.controls.public_access_fully_blocked", Rationale: "s3_bucket_public_access check maps to Stave S3 exposure controls"},
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.console_access.mfa_enabled", Rationale: "iam_user_mfa_enabled maps to Stave IAM MFA controls"},
		},
	},
	{
		Name:        "weirdaal",
		Description: "AWS attack library — reconnaissance, persistence, and exfiltration modules",
		Reference:   "https://github.com/carnal0wnage/weirdAAL",
		Prerequisites: []Prerequisite{
			{Capability: "s3_data_access", FieldPath: "properties.storage.access.public_read", Rationale: "s3_list and s3_download target readable public buckets"},
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.service_wildcards_granted", Rationale: "iam_enum targets overly broad IAM permissions"},
			{Capability: "rds_data_access", FieldPath: "properties.database.network.publicly_accessible", Rationale: "rds_enum targets publicly accessible databases"},
		},
	},
	{
		Name:        "cloudgoat",
		Description: "Rhino Security Labs vulnerable-by-design AWS scenarios — 10 validated attack paths",
		Reference:   "https://github.com/RhinoSecurityLabs/cloudgoat",
		Prerequisites: []Prerequisite{
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.has_admin_access", Rationale: "iam_privesc_by_attachment and iam_privesc_by_rollback exploit overprivileged roles"},
			{Capability: "ec2_code_execution", FieldPath: "properties.compute.imds.version", Rationale: "cloud_breach_s3 steals metadata credentials via IMDSv1"},
			{Capability: "s3_data_access", FieldPath: "properties.storage.access.public_read", Rationale: "cloud_breach_s3 exfiltrates from misconfigured buckets"},
			{Capability: "secret_store_access", FieldPath: "properties.secret.access.rotation_enabled", Rationale: "codebuild_secrets and sns_secrets harvest exposed secrets"},
			{Capability: "container_code_execution", FieldPath: "properties.compute.task_definition.network_mode", Rationale: "ecs_efs_attack exploits ECS task configuration for lateral movement"},
		},
	},
	{
		Name:        "enumerate-iam",
		Description: "Brute-force enumeration of IAM permissions for a given set of AWS credentials",
		Reference:   "https://github.com/andresriancho/enumerate-iam",
		Prerequisites: []Prerequisite{
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.credential.access_key_age_days", Rationale: "enumerates which API calls succeed with stolen long-term credentials"},
		},
	},
	{
		Name:        "scoutsuite",
		Description: "Multi-cloud security auditing tool — maps misconfigurations across AWS services",
		Reference:   "https://github.com/nccgroup/ScoutSuite",
		Prerequisites: []Prerequisite{
			{Capability: "s3_data_access", FieldPath: "properties.storage.controls.public_access_fully_blocked", Rationale: "scouts s3 bucket policies and ACLs for public exposure"},
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.has_admin_access", Rationale: "audits IAM policies for overprivileged roles"},
			{Capability: "network_access_ec2", FieldPath: "properties.compute.security_group.ingress_unrestricted", Rationale: "maps security group rules for unrestricted ingress"},
		},
	},
	{
		Name:        "pmapper",
		Description: "AWS IAM privilege escalation path finder using graph analysis",
		Reference:   "https://github.com/nccgroup/PMapper",
		Prerequisites: []Prerequisite{
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.escalation", Rationale: "builds IAM privilege escalation graph from policy analysis"},
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.has_admin_access", Rationale: "identifies admin-equivalent roles reachable via escalation"},
		},
	},
	{
		Name:        "trufflehog",
		Description: "Credential and secret scanner for git repos, S3 buckets, and filesystems",
		Reference:   "https://github.com/trufflesecurity/trufflehog",
		Prerequisites: []Prerequisite{
			{Capability: "secret_store_access", FieldPath: "properties.secret.access.rotation_enabled", Rationale: "finds hardcoded credentials and API keys in exposed resources"},
			{Capability: "s3_data_access", FieldPath: "properties.storage.access.public_read", Rationale: "scans publicly readable S3 buckets for leaked secrets"},
		},
	},
	{
		Name:        "endgame",
		Description: "AWS resource policy backdoor tool — creates persistent cross-account access",
		Reference:   "https://github.com/DavidDikworworst/endgame",
		Prerequisites: []Prerequisite{
			{Capability: "s3_data_access", FieldPath: "properties.storage.access.public_read", Rationale: "backdoors S3 bucket policies for persistent cross-account access"},
			{Capability: "iam_credential_theft", FieldPath: "properties.identity.policies.service_wildcards_granted", Rationale: "exploits overly broad resource policies to create backdoor access"},
		},
	},
}

// ToolNamesForCapability returns tool names matching a capability,
// satisfying the attackpath.ToolLookup interface.
func (r *Registry) ToolNamesForCapability(capability string) []string {
	tools := r.ToolsForCapability(capability)
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	return names
}

func sortTools(tools []Tool) {
	for i := 1; i < len(tools); i++ {
		for j := i; j > 0 && tools[j].Name < tools[j-1].Name; j-- {
			tools[j], tools[j-1] = tools[j-1], tools[j]
		}
	}
}
