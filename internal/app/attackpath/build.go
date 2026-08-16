// Package attackpath produces a structured attack path graph export
// from active chain findings. An external program performs graph
// algorithms — Stave only emits nodes and edges.
package attackpath

import (
	"cmp"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Graph is the top-level attack path export.
type Graph struct {
	GeneratedAt  string       `json:"generated_at"`
	Snapshot     string       `json:"snapshot"`
	Assessment   string       `json:"assessment"`
	Capabilities []Capability `json:"capabilities"`
	ChainNodes   []ChainNode  `json:"chain_nodes"`
	Edges        []Edge       `json:"edges"`
	Assets       []AssetRef   `json:"assets"`
}

// Capability describes a named attacker capability.
type Capability struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// ChainNode represents a chain in the graph.
type ChainNode struct {
	ChainID         string           `json:"chain_id"`
	Name            string           `json:"name"`
	Severity        string           `json:"severity"`
	Status          string           `json:"status"`
	Preconditions   []string         `json:"preconditions"`
	Postconditions  []string         `json:"postconditions"`
	MemberControls  []MemberControl  `json:"member_controls"`
	ToolAnnotations []ToolAnnotation `json:"tool_annotations,omitempty"`
}

// ToolAnnotation records an offensive tool whose prerequisites
// overlap with this chain's capabilities.
type ToolAnnotation struct {
	ToolName            string   `json:"tool_name"`
	MatchedCapabilities []string `json:"matched_capabilities"`
}

// MemberControl is a control within a chain node.
type MemberControl struct {
	ControlID   string `json:"control_id"`
	Remediation string `json:"remediation"`
}

// Edge connects two chains via a shared capability.
type Edge struct {
	FromChain     string `json:"from_chain"`
	ToChain       string `json:"to_chain"`
	ViaCapability string `json:"via_capability"`
	Description   string `json:"description"`
}

// AssetRef describes an asset touched by active chains.
type AssetRef struct {
	AssetID             string   `json:"asset_id"`
	AssetType           string   `json:"asset_type"`
	Classification      string   `json:"classification"`
	ActiveChainFindings []string `json:"active_chain_findings"`
}

// ActiveFinding is a minimal representation of an active compound finding.
type ActiveFinding struct {
	ChainID         string
	ControlsFailing []kernel.ControlID
}

// ToolLookup returns tool names whose prerequisites include the given
// capability. Implementations live in toolmap.Registry; nil disables
// tool annotations on the graph.
type ToolLookup interface {
	ToolNamesForCapability(capability string) []string
}

// BuildInput holds the data needed to build an attack path graph.
type BuildInput struct {
	GeneratedAt    string
	SnapshotPath   string
	AssessmentPath string
	Chains         []policy.ChainDefinition
	Findings       []ActiveFinding
	ControlLookup  map[string]*policy.ControlDefinition
	Tools          ToolLookup
}

// Build produces an attack path graph from active chain findings.
func Build(input BuildInput) *Graph {
	activeChains := make(map[string]struct{}, len(input.Findings))
	for _, f := range input.Findings {
		activeChains[f.ChainID] = struct{}{}
	}

	// Collect capabilities referenced by active annotated chains.
	capSet := make(map[string]struct{})
	var nodes []ChainNode
	for i := range input.Chains {
		ch := &input.Chains[i]
		status := "inactive"
		if _, ok := activeChains[string(ch.ID)]; ok {
			status = "active"
		}

		var members []MemberControl
		for _, cid := range ch.ControlIDs {
			mc := MemberControl{ControlID: string(cid)}
			if ctl, ok := input.ControlLookup[string(cid)]; ok && ctl != nil && ctl.Remediation != nil {
				mc.Remediation = ctl.Remediation.Action
			}
			members = append(members, mc)
		}

		node := ChainNode{
			ChainID:        string(ch.ID),
			Name:           strings.ReplaceAll(string(ch.ID), "_", " "),
			Severity:       ch.CompoundSeverity.String(),
			Status:         status,
			Preconditions:  ch.Preconditions,
			Postconditions: ch.Postconditions,
			MemberControls: members,
		}
		if node.Preconditions == nil {
			node.Preconditions = []string{}
		}
		if node.Postconditions == nil {
			node.Postconditions = []string{}
		}
		nodes = append(nodes, node)

		if status == "active" {
			for _, c := range ch.Preconditions {
				capSet[c] = struct{}{}
			}
			for _, c := range ch.Postconditions {
				capSet[c] = struct{}{}
			}
		}
	}

	// Annotate nodes with matching offensive tools.
	if input.Tools != nil {
		annotateTools(nodes, input.Chains, input.Tools)
	}

	// Derive edges: postcondition of A matches precondition of B.
	// Only active, annotated chains produce edges.
	var edges []Edge
	for i := range input.Chains {
		a := &input.Chains[i]
		if _, ok := activeChains[string(a.ID)]; !ok || len(a.Postconditions) == 0 {
			continue
		}
		for j := range input.Chains {
			b := &input.Chains[j]
			_, isActiveB := activeChains[string(b.ID)]
			if a.ID == b.ID || !isActiveB || len(b.Preconditions) == 0 {
				continue
			}
			for _, post := range a.Postconditions {
				for _, pre := range b.Preconditions {
					if post == pre {
						edges = append(edges, Edge{
							FromChain:     string(a.ID),
							ToChain:       string(b.ID),
							ViaCapability: post,
							Description:   capLabel(post) + " enables " + strings.ReplaceAll(string(b.ID), "_", " "),
						})
					}
				}
			}
		}
	}

	slices.SortFunc(edges, func(a, b Edge) int {
		return cmp.Or(
			cmp.Compare(a.FromChain, b.FromChain),
			cmp.Compare(a.ToChain, b.ToChain),
			cmp.Compare(a.ViaCapability, b.ViaCapability),
		)
	})

	// Build capability list from referenced capabilities.
	var caps []Capability
	for cap := range capSet {
		caps = append(caps, Capability{
			ID:          cap,
			Label:       capLabel(cap),
			Description: capDescription(cap),
		})
	}
	slices.SortFunc(caps, func(a, b Capability) int { return cmp.Compare(a.ID, b.ID) })

	return &Graph{
		GeneratedAt:  input.GeneratedAt,
		Snapshot:     input.SnapshotPath,
		Assessment:   input.AssessmentPath,
		Capabilities: caps,
		ChainNodes:   nodes,
		Edges:        edges,
		Assets:       []AssetRef{}, // populated by caller if snapshot data available
	}
}

var (
	//nolint:gosec // G101: not credentials — ATT&CK capability labels
	capLabels = map[string]string{
		"audit_trail_destroyed":                  "Audit Trail Destroyed",
		"automation_hijack":                      "Automation Hijack",
		"aws_root_access":                        "AWS Root Access",
		"az_failure":                             "Availability Zone Failure",
		"bucket_name_available_for_registration": "Bucket Name Available",
		"cdn_bypass_data_access":                 "CDN Bypass Data Access",
		"cloudfront_origin_configured":           "CloudFront Origin Configured",
		"cloudtrail_data_access":                 "CloudTrail Data Access",
		"container_code_execution":               "Container Code Execution",
		"control_plane_code_execution":           "Control Plane Code Execution",
		"credential_access":                      "Credential Access",
		"cross_account_data_exfiltration":        "Cross-Account Data Exfiltration",
		"cross_account_destination_configured":   "Cross-Account Destination Configured",
		"cross_account_injection":                "Cross-Account Injection",
		"data_access":                            "Data Access",
		"data_destruction":                       "Data Destruction",
		"data_exfiltration":                      "Data Exfiltration",
		"data_exfiltration_via_hijack":           "Data Exfiltration via Hijack",
		"data_in_transit_exposure":               "Data in Transit Exposure",
		"data_stream_capture":                    "Data Stream Capture",
		"data_warehouse_compromise":              "Data Warehouse Compromise",
		"database_compromise":                    "Database Compromise",
		"db_credential_theft":                    "Database Credentials",
		"detection_blindness":                    "Detection Blindness",
		"detection_evasion":                      "Detection Evasion",
		"detection_fragmented":                   "Detection Fragmented",
		"detection_without_response":             "Detection Without Response",
		"domain_takeover":                        "Domain Takeover",
		"ec2_code_execution":                     "EC2 Code Execution",
		"encryption_bypass":                      "Encryption Bypass",
		"iam_credential_theft":                   "IAM Credentials",
		"indirect_data_rerouting":                "Indirect Data Rerouting",
		"initial_access":                         "Initial Access",
		"internet_access":                        "Internet Access",
		"invisible_data_exfiltration":            "Invisible Data Exfiltration",
		"k8s_cluster_admin":                      "K8s Cluster Admin",
		"k8s_service_account_token":              "K8s Service Account Token",
		"kms_encryption_configured":              "KMS Encryption Configured",
		"kms_key_compromise":                     "KMS Key Compromise",
		"lateral_movement":                       "Lateral Movement",
		"network_access_ec2":                     "EC2 Network Access",
		"network_access_eks":                     "EKS Network Access",
		"network_access_lambda":                  "Lambda Network Access",
		"network_access_rds":                     "RDS Network Access",
		"network_access_vpc":                     "VPC Network Access",
		"no_router_update_permission":            "No Router Update Permission",
		"org_admin_access":                       "Organization Admin Access",
		"rds_data_access":                        "RDS Data Access",
		"resource_policy_escalation":             "Resource Policy Escalation",
		"s3_data_access":                         "S3 Data Access",
		"s3_delete_bucket_permission":            "S3 Delete Bucket Permission",
		"s3_replication_configured":              "S3 Replication Configured",
		"scp_governance_configured":              "SCP Governance Configured",
		"secret_store_access":                    "Secret Store Access",
		"security_telemetry_exfiltration":        "Security Telemetry Exfiltration",
		"service_disruption":                     "Service Disruption",
		"shadow_admin_access":                    "Shadow Admin Access",
		"shadow_infrastructure":                  "Shadow Infrastructure",
		"supply_chain_compromise":                "Supply Chain Compromise",
		"ungoverned_operation":                   "Ungoverned Operation",
		"vpc_instance_compromise":                "VPC Instance Compromise",
	}

	//nolint:gosec // G101: not credentials — ATT&CK capability descriptions
	capDescriptions = map[string]string{
		"audit_trail_destroyed":                  "Audit logging disabled or tampered with",
		"automation_hijack":                      "Attacker hijacks automated workflows or CI/CD pipelines",
		"aws_root_access":                        "AWS root account access obtained",
		"az_failure":                             "Availability zone failure exploited for failover manipulation",
		"bucket_name_available_for_registration": "S3 bucket name available for adversarial registration",
		"cdn_bypass_data_access":                 "Data accessed by bypassing CDN origin restrictions",
		"cloudfront_origin_configured":           "CloudFront distribution configured with origin access",
		"cloudtrail_data_access":                 "Attacker can read CloudTrail audit logs",
		"container_code_execution":               "Arbitrary code execution in containers",
		"control_plane_code_execution":           "Code execution on AWS control plane services",
		"credential_access":                      "Valid credentials obtained through any vector",
		"cross_account_data_exfiltration":        "Data exfiltrated to an attacker-controlled account",
		"cross_account_destination_configured":   "Cross-account replication or transfer destination exists",
		"cross_account_injection":                "Attacker injects resources or data across account boundary",
		"data_access":                            "Attacker can read sensitive data stores",
		"data_destruction":                       "Attacker can destroy data without recovery",
		"data_exfiltration":                      "Data transferred out of the environment",
		"data_exfiltration_via_hijack":           "Data exfiltrated by hijacking an infrastructure component",
		"data_in_transit_exposure":               "Unencrypted data exposed during transfer",
		"data_stream_capture":                    "Real-time data streams intercepted or redirected",
		"data_warehouse_compromise":              "Data warehouse (Redshift, Athena) compromised",
		"database_compromise":                    "Database fully compromised — read, write, or destroy",
		"db_credential_theft":                    "Database credentials obtained",
		"detection_blindness":                    "Security monitoring completely ineffective",
		"detection_evasion":                      "Attacker evades detection mechanisms",
		"detection_fragmented":                   "Detection coverage has gaps across services or regions",
		"detection_without_response":             "Threats detected but no automated response configured",
		"domain_takeover":                        "DNS domain or subdomain taken over by attacker",
		"ec2_code_execution":                     "Arbitrary code execution on EC2 instances",
		"encryption_bypass":                      "Encryption controls circumvented or weakened",
		"iam_credential_theft":                   "Valid AWS IAM credentials obtained",
		"indirect_data_rerouting":                "Data rerouted through attacker-controlled infrastructure",
		"initial_access":                         "Attacker gains first foothold in the environment",
		"internet_access":                        "Attacker reachable from the public internet",
		"invisible_data_exfiltration":            "Data exfiltrated without triggering any alerts",
		"k8s_cluster_admin":                      "Kubernetes cluster-admin privileges obtained",
		"k8s_service_account_token":              "Valid Kubernetes service account token obtained",
		"kms_encryption_configured":              "KMS encryption is configured on the resource",
		"kms_key_compromise":                     "KMS key compromised — attacker can decrypt or re-encrypt",
		"lateral_movement":                       "Attacker moves between resources within the environment",
		"network_access_ec2":                     "Attacker can reach EC2 instances on internal ports",
		"network_access_eks":                     "Attacker can reach EKS API server or pods",
		"network_access_lambda":                  "Attacker can invoke Lambda functions",
		"network_access_rds":                     "Attacker can reach RDS database endpoints",
		"network_access_vpc":                     "Attacker can reach services within the VPC",
		"no_router_update_permission":            "No permission to update VPC route tables",
		"org_admin_access":                       "Attacker controls the AWS organization management account",
		"rds_data_access":                        "Attacker can query database contents",
		"resource_policy_escalation":             "Attacker escalates privileges via resource policy manipulation",
		"s3_data_access":                         "Attacker can read S3 bucket contents",
		"s3_delete_bucket_permission":            "Permission to delete S3 buckets",
		"s3_replication_configured":              "S3 cross-region or cross-account replication is active",
		"scp_governance_configured":              "Service control policies enforce governance boundaries",
		"secret_store_access":                    "Access to Secrets Manager or Parameter Store",
		"security_telemetry_exfiltration":        "Security telemetry data exfiltrated or redirected",
		"service_disruption":                     "AWS service availability impacted",
		"shadow_admin_access":                    "Attacker has admin-equivalent access via indirect path",
		"shadow_infrastructure":                  "Unauthorized infrastructure deployed alongside legitimate resources",
		"supply_chain_compromise":                "Upstream dependency or build pipeline compromised",
		"ungoverned_operation":                   "Operations executing outside governance controls",
		"vpc_instance_compromise":                "EC2 instance within VPC compromised",
	}
)

func capLabel(id string) string {
	if l, ok := capLabels[id]; ok {
		return l
	}
	return strings.ReplaceAll(id, "_", " ")
}

func capDescription(id string) string {
	if d, ok := capDescriptions[id]; ok {
		return d
	}
	return ""
}

// annotateTools matches each chain node's capabilities against the
// tool registry and records which tools could exploit each chain.
func annotateTools(nodes []ChainNode, chains []policy.ChainDefinition, tools ToolLookup) {
	for i := range nodes {
		caps := make(map[string]struct{})
		ch := &chains[i]
		for _, c := range ch.Preconditions {
			caps[c] = struct{}{}
		}
		for _, c := range ch.Postconditions {
			caps[c] = struct{}{}
		}

		toolMatches := make(map[string][]string) // tool name → matched caps
		for cap := range caps {
			for _, name := range tools.ToolNamesForCapability(cap) {
				toolMatches[name] = append(toolMatches[name], cap)
			}
		}
		if len(toolMatches) == 0 {
			continue
		}

		names := make([]string, 0, len(toolMatches))
		for name := range toolMatches {
			names = append(names, name)
		}
		slices.Sort(names)

		for _, name := range names {
			matched := toolMatches[name]
			slices.Sort(matched)
			nodes[i].ToolAnnotations = append(nodes[i].ToolAnnotations, ToolAnnotation{
				ToolName:            name,
				MatchedCapabilities: matched,
			})
		}
	}
}
