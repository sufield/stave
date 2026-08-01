package network

import (
	"errors"
	"fmt"
	"time"
)

// ProofResult is the outcome of a bastion routing proof.
type ProofResult struct {
	Property        string          `json:"property"`
	Result          string          `json:"result"` // "UNSAT" | "SAT"
	Interpretation  string          `json:"interpretation"`
	ProductionHosts int             `json:"production_hosts"`
	BastionHosts    int             `json:"bastion_hosts"`
	SSHPaths        int             `json:"ssh_paths"`
	Counterexample  *Counterexample `json:"counterexample,omitempty"`
	SolveTimeMs     int64           `json:"solve_time_ms"`
}

// Counterexample is a concrete bastion bypass path.
type Counterexample struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	PathType    string `json:"path_type"`
	RuleSG      string `json:"rule_sg"`
	RuleSource  string `json:"rule_source"`
	Explanation string `json:"explanation"`
	Remediation string `json:"remediation"`
}

// EnumerateResult is the output of SSH entry point enumeration.
type EnumerateResult struct {
	Scope           string    `json:"scope"`
	Port            int       `json:"port"`
	ProductionHosts int       `json:"production_hosts"`
	Paths           []SSHPath `json:"paths"`
}

// ErrVacuousProof is returned when a proof cannot run because the
// scope sets (production hosts, bastion hosts) are empty.
var ErrVacuousProof = errors.New("vacuous proof")

// ProveBastionSSH checks whether all SSH paths to production hosts
// traverse a bastion. Returns UNSAT if bastion routing holds,
// SAT with a counterexample if a bypass exists.
//
// Returns ErrVacuousProof when production or bastion hosts are empty —
// the property cannot be proved without both scope sets populated.
func (g *Graph) ProveBastionSSH(port int) (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	bastions := g.BastionHosts()

	if len(prod) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:environment=production — cannot prove bastion routing", ErrVacuousProof)
	}
	if len(bastions) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:role=bastion — cannot prove bastion routing", ErrVacuousProof)
	}

	bastionIDs := make(map[string]bool, len(bastions))
	for _, b := range bastions {
		bastionIDs[b.ID] = true
	}

	result := &ProofResult{
		Property:        "bastion-ssh",
		ProductionHosts: len(prod),
		BastionHosts:    len(bastions),
	}

	// Find all SSH paths to production from non-bastion, non-production sources.
	for _, dst := range prod {
		for _, src := range g.allHosts() {
			if src.ID == dst.ID || src.IsProduction() || bastionIDs[src.ID] {
				continue
			}
			if ok, pathType := g.CanReach(src.ID, dst.ID, port); ok {
				result.SSHPaths++
				ruleSG, ruleSource := g.findRule(src, dst, port)
				result.Counterexample = &Counterexample{
					Source:      src.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    pathType,
					RuleSG:      ruleSG,
					RuleSource:  ruleSource,
					Explanation: buildExplanation(src, dst, pathType, ruleSG, ruleSource),
					Remediation: buildRemediation(ruleSG, ruleSource, bastions),
				}
				result.Result = "SAT"
				result.Interpretation = "Bastion bypass exists — a non-bastion host can SSH to production without traversing a bastion."
				result.SolveTimeMs = time.Since(start).Milliseconds()
				return result, nil
			}
		}

		// Check external entry (0.0.0.0/0).
		if ce := g.findExternalBypass(dst, port); ce != nil {
			result.SSHPaths++
			result.Counterexample = ce
			result.Result = "SAT"
			result.Interpretation = "Bastion bypass exists — production host is directly SSH-accessible from the internet."
			result.SolveTimeMs = time.Since(start).Milliseconds()
			return result, nil
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "All SSH paths to production traverse a bastion host."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

func (g *Graph) findExternalBypass(dst *Host, port int) *Counterexample {
	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if rule.Direction != "ingress" || rule.Port != port {
				continue
			}
			if rule.SourceType != "cidr" || (rule.SourceValue != "0.0.0.0/0" && rule.SourceValue != "::/0") {
				continue
			}
			return &Counterexample{
				Source:      "0.0.0.0/0 (internet)",
				Destination: dst.ID,
				Port:        port,
				PathType:    "external",
				RuleSG:      dstSG,
				RuleSource:  "0.0.0.0/0",
				Explanation: "Production host " + dst.ID + " accepts SSH from the internet (0.0.0.0/0) on " + dstSG + ". No bastion in the path.",
				Remediation: "Remove SSH ingress from 0.0.0.0/0 on " + dstSG + ". Restrict to bastion SG reference only.",
			}
		}
	}
	return nil
}

func buildExplanation(src, dst *Host, pathType, ruleSG, ruleSource string) string {
	switch pathType {
	case "cross-vpc":
		return "Host " + src.ID + " (vpc:" + src.VPCID + ") can SSH to production host " +
			dst.ID + " (vpc:" + dst.VPCID + ") via VPC peering. Security group " +
			ruleSG + " allows SSH from " + ruleSource + ". No bastion in the path."
	default:
		return "Host " + src.ID + " can SSH to production host " +
			dst.ID + " via " + ruleSG + " allowing SSH from " + ruleSource + ". No bastion in the path."
	}
}

func buildRemediation(ruleSG, ruleSource string, bastions []*Host) string {
	rem := "Remove SSH ingress rule (" + ruleSource + ") on " + ruleSG + "."
	if len(bastions) > 0 {
		rem += " Replace with SSH from bastion SG only."
	}
	return rem
}
