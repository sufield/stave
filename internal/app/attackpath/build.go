// Package attackpath produces a structured attack path graph export
// from active chain findings. An external program performs graph
// algorithms — Stave only emits nodes and edges.
package attackpath

import (
	"sort"
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
	ChainID        string          `json:"chain_id"`
	Name           string          `json:"name"`
	Severity       string          `json:"severity"`
	Status         string          `json:"status"`
	Preconditions  []string        `json:"preconditions"`
	Postconditions []string        `json:"postconditions"`
	MemberControls []MemberControl `json:"member_controls"`
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

// BuildInput holds the data needed to build an attack path graph.
type BuildInput struct {
	GeneratedAt    string
	SnapshotPath   string
	AssessmentPath string
	Chains         []policy.ChainDefinition
	Findings       []ActiveFinding
	ControlLookup  map[string]*policy.ControlDefinition
}

// Build produces an attack path graph from active chain findings.
func Build(input BuildInput) *Graph {
	activeChains := make(map[string]bool, len(input.Findings))
	for _, f := range input.Findings {
		activeChains[f.ChainID] = true
	}

	// Collect capabilities referenced by active annotated chains.
	capSet := make(map[string]bool)
	var nodes []ChainNode
	for i := range input.Chains {
		ch := &input.Chains[i]
		status := "inactive"
		if activeChains[ch.ID] {
			status = "active"
		}

		var members []MemberControl
		for _, cid := range ch.ControlIDs {
			mc := MemberControl{ControlID: string(cid)}
			if ctl, ok := input.ControlLookup[string(cid)]; ok && ctl.Remediation != nil {
				mc.Remediation = ctl.Remediation.Action
			}
			members = append(members, mc)
		}

		node := ChainNode{
			ChainID:        ch.ID,
			Name:           strings.ReplaceAll(ch.ID, "_", " "),
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
				capSet[c] = true
			}
			for _, c := range ch.Postconditions {
				capSet[c] = true
			}
		}
	}

	// Derive edges: postcondition of A matches precondition of B.
	// Only active, annotated chains produce edges.
	var edges []Edge
	for i := range input.Chains {
		a := &input.Chains[i]
		if !activeChains[a.ID] || len(a.Postconditions) == 0 {
			continue
		}
		for j := range input.Chains {
			b := &input.Chains[j]
			if a.ID == b.ID || !activeChains[b.ID] || len(b.Preconditions) == 0 {
				continue
			}
			for _, post := range a.Postconditions {
				for _, pre := range b.Preconditions {
					if post == pre {
						edges = append(edges, Edge{
							FromChain:     a.ID,
							ToChain:       b.ID,
							ViaCapability: post,
							Description:   capLabel(post) + " enables " + strings.ReplaceAll(b.ID, "_", " "),
						})
					}
				}
			}
		}
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromChain != edges[j].FromChain {
			return edges[i].FromChain < edges[j].FromChain
		}
		return edges[i].ToChain < edges[j].ToChain
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
	sort.Slice(caps, func(i, j int) bool { return caps[i].ID < caps[j].ID })

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

func capLabel(id string) string {
	labels := map[string]string{ //nolint:gosec // G101: not credentials — ATT&CK capability labels
		"internet_access":           "Internet Access",
		"network_access_vpc":        "VPC Network Access",
		"network_access_ec2":        "EC2 Network Access",
		"network_access_rds":        "RDS Network Access",
		"network_access_eks":        "EKS Network Access",
		"network_access_lambda":     "Lambda Network Access",
		"iam_credential_theft":      "IAM Credentials",
		"aws_root_access":           "AWS Root Access",
		"k8s_service_account_token": "K8s Service Account Token",
		"db_credential_theft":       "Database Credentials",
		"secret_store_access":       "Secret Store Access",
		"ec2_code_execution":        "EC2 Code Execution",
		"container_code_execution":  "Container Code Execution",
		"k8s_cluster_admin":         "K8s Cluster Admin",
		"s3_data_access":            "S3 Data Access",
		"rds_data_access":           "RDS Data Access",
		"cloudtrail_data_access":    "CloudTrail Data Access",
		"data_destruction":          "Data Destruction",
		"audit_trail_destroyed":     "Audit Trail Destroyed",
	}
	if l, ok := labels[id]; ok {
		return l
	}
	return strings.ReplaceAll(id, "_", " ")
}

func capDescription(id string) string {
	desc := map[string]string{ //nolint:gosec // G101: not credentials — ATT&CK capability descriptions
		"internet_access":           "Attacker reachable from the public internet",
		"network_access_vpc":        "Attacker can reach services within the VPC",
		"network_access_ec2":        "Attacker can reach EC2 instances on internal ports",
		"network_access_rds":        "Attacker can reach RDS database endpoints",
		"network_access_eks":        "Attacker can reach EKS API server or pods",
		"network_access_lambda":     "Attacker can invoke Lambda functions",
		"iam_credential_theft":      "Valid AWS IAM credentials obtained",
		"aws_root_access":           "AWS root account access obtained",
		"k8s_service_account_token": "Valid Kubernetes service account token obtained",
		"db_credential_theft":       "Database credentials obtained",
		"secret_store_access":       "Access to Secrets Manager or Parameter Store",
		"ec2_code_execution":        "Arbitrary code execution on EC2 instances",
		"container_code_execution":  "Arbitrary code execution in containers",
		"k8s_cluster_admin":         "Kubernetes cluster-admin privileges obtained",
		"s3_data_access":            "Attacker can read S3 bucket contents",
		"rds_data_access":           "Attacker can query database contents",
		"cloudtrail_data_access":    "Attacker can read CloudTrail audit logs",
		"data_destruction":          "Attacker can destroy data without recovery",
		"audit_trail_destroyed":     "Audit logging disabled or tampered with",
	}
	if d, ok := desc[id]; ok {
		return d
	}
	return ""
}
