package network

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ProofResult is the outcome of a network safety property proof.
type ProofResult struct {
	Property        string          `json:"property"`
	Result          string          `json:"result"` // "UNSAT" | "SAT"
	Interpretation  string          `json:"interpretation"`
	ProductionHosts int             `json:"production_hosts,omitempty"`
	BastionHosts    int             `json:"bastion_hosts,omitempty"`
	SSHPaths        int             `json:"ssh_paths,omitempty"`
	Scope           map[string]int  `json:"scope,omitempty"`
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

// ProveProdDevIsolation checks that no network path exists between
// production and development environments. Returns UNSAT if isolation
// holds, SAT with a counterexample if a cross-environment path exists.
func (g *Graph) ProveProdDevIsolation() (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	dev := g.DevelopmentHosts()

	if len(prod) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:environment=production", ErrVacuousProof)
	}
	if len(dev) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:environment=development", ErrVacuousProof)
	}

	result := &ProofResult{
		Property: "prod-dev-isolation",
		Scope:    map[string]int{"production_hosts": len(prod), "development_hosts": len(dev)},
	}

	// Check both directions: prod→dev and dev→prod.
	pairs := [][2][]*Host{{prod, dev}, {dev, prod}}
	for _, pair := range pairs {
		for _, src := range pair[0] {
			for _, dst := range pair[1] {
				ok, pathType, port := g.canReachAnyPort(src.ID, dst.ID)
				if !ok {
					continue
				}
				ruleSG, ruleSource := g.findRule(src, dst, port)
				result.Result = "SAT"
				result.Interpretation = "Production-development isolation violated — a cross-environment path exists."
				result.Counterexample = &Counterexample{
					Source:      src.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    pathType,
					RuleSG:      ruleSG,
					RuleSource:  ruleSource,
					Explanation: "Host " + src.ID + " (" + src.Tags["stave:environment"] + ") can reach " + dst.ID + " (" + dst.Tags["stave:environment"] + ") via " + pathType + ".",
					Remediation: "Remove cross-environment ingress rule on " + ruleSG + ". Ensure production and development VPCs have no peering or broad CIDR rules.",
				}
				result.SolveTimeMs = time.Since(start).Milliseconds()
				return result, nil
			}
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "Production and development environments are network-isolated."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// ProveDatabaseIsolation checks that no host outside the database VPC
// can reach a database-tier host. Returns UNSAT if isolation holds,
// SAT with a counterexample if an external path exists.
func (g *Graph) ProveDatabaseIsolation() (*ProofResult, error) {
	start := time.Now()

	dbHosts := g.DatabaseHosts()
	if len(dbHosts) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:tier=database", ErrVacuousProof)
	}

	result := &ProofResult{
		Property: "database-isolation",
		Scope:    map[string]int{"database_hosts": len(dbHosts)},
	}

	for _, dst := range dbHosts {
		// Check cross-VPC reachability from any non-same-VPC host.
		for _, src := range g.allHosts() {
			if src.ID == dst.ID || src.VPCID == dst.VPCID {
				continue
			}
			if ok, pathType, port := g.canReachAnyPort(src.ID, dst.ID); ok {
				ruleSG, ruleSource := g.findRule(src, dst, port)
				result.Result = "SAT"
				result.Interpretation = "Database isolation violated — a host outside the database VPC can reach a database host."
				result.Counterexample = &Counterexample{
					Source:      src.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    pathType,
					RuleSG:      ruleSG,
					RuleSource:  ruleSource,
					Explanation: "Host " + src.ID + " (vpc:" + src.VPCID + ") can reach database host " + dst.ID + " (vpc:" + dst.VPCID + ") via " + pathType + ".",
					Remediation: "Remove cross-VPC ingress to database SG " + ruleSG + ". Restrict to application-tier SG references within the same VPC.",
				}
				result.SolveTimeMs = time.Since(start).Milliseconds()
				return result, nil
			}
		}

		// Check external entry (0.0.0.0/0 or ::/0 on any port).
		for _, dstSG := range dst.SGIDs {
			for _, rule := range g.SGRules[dstSG] {
				if rule.Direction != "ingress" {
					continue
				}
				if rule.SourceType == "cidr" && (rule.SourceValue == "0.0.0.0/0" || rule.SourceValue == "::/0") {
					result.Result = "SAT"
					result.Interpretation = "Database isolation violated — database host is directly accessible from the internet."
					result.Counterexample = &Counterexample{
						Source:      rule.SourceValue + " (internet)",
						Destination: dst.ID,
						Port:        rule.Port,
						PathType:    "external",
						RuleSG:      dstSG,
						RuleSource:  rule.SourceValue,
						Explanation: "Database host " + dst.ID + " accepts traffic from " + rule.SourceValue + " on port " + strconv.Itoa(rule.Port) + " via " + dstSG + ".",
						Remediation: "Remove internet ingress on " + dstSG + ". Database hosts must not be reachable from the internet.",
					}
					result.SolveTimeMs = time.Since(start).Milliseconds()
					return result, nil
				}
			}
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "All database hosts are isolated within their VPC — no cross-VPC or internet paths exist."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// ProveTransitiveSSH checks whether any non-bastion host can act as an
// SSH relay to reach production (2+ hop: internet/host -> relay -> production
// where relay is not a bastion).
func (g *Graph) ProveTransitiveSSH(port int) (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	bastions := g.BastionHosts()

	if len(prod) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:environment=production — cannot prove transitive SSH", ErrVacuousProof)
	}

	bastionIDs := make(map[string]bool, len(bastions))
	for _, b := range bastions {
		bastionIDs[b.ID] = true
	}

	result := &ProofResult{
		Property:        "transitive-ssh",
		ProductionHosts: len(prod),
		BastionHosts:    len(bastions),
	}

	for _, dst := range prod {
		for _, relay := range g.allHosts() {
			if relay.ID == dst.ID || relay.IsProduction() || bastionIDs[relay.ID] {
				continue
			}
			if ok, _ := g.CanReach(relay.ID, dst.ID, port); !ok {
				continue
			}

			// Relay can reach prod. Check if relay is reachable from the internet.
			if ce := g.findExternalBypass(relay, port); ce != nil {
				ruleSG, ruleSource := g.findRule(relay, dst, port)
				result.Result = "SAT"
				result.Interpretation = "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production."
				result.Counterexample = &Counterexample{
					Source:      "0.0.0.0/0 -> " + relay.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    "transitive",
					RuleSG:      ruleSG,
					RuleSource:  ruleSource,
					Explanation: "Host " + relay.ID + " is SSH-accessible from the internet and can reach production host " + dst.ID + " on port " + strconv.Itoa(port) + ". Two-hop path: internet -> " + relay.ID + " -> " + dst.ID + ".",
					Remediation: "Remove SSH ingress from 0.0.0.0/0 on " + relay.ID + " or remove its access to production host " + dst.ID + ".",
				}
				result.SolveTimeMs = time.Since(start).Milliseconds()
				return result, nil
			}

			// Check if any other non-prod, non-bastion host can reach the relay.
			for _, src := range g.allHosts() {
				if src.ID == relay.ID || src.ID == dst.ID || src.IsProduction() || bastionIDs[src.ID] {
					continue
				}
				if ok, _ := g.CanReach(src.ID, relay.ID, port); ok {
					ruleSG, ruleSource := g.findRule(relay, dst, port)
					result.Result = "SAT"
					result.Interpretation = "Transitive SSH path exists — a non-bastion host can relay SSH to production via an intermediate host."
					result.Counterexample = &Counterexample{
						Source:      src.ID + " -> " + relay.ID,
						Destination: dst.ID,
						Port:        port,
						PathType:    "transitive",
						RuleSG:      ruleSG,
						RuleSource:  ruleSource,
						Explanation: "Host " + src.ID + " can reach " + relay.ID + ", which can reach production host " + dst.ID + " on port " + strconv.Itoa(port) + ". Two-hop path: " + src.ID + " -> " + relay.ID + " -> " + dst.ID + ".",
						Remediation: "Remove SSH access from " + src.ID + " to " + relay.ID + " or from " + relay.ID + " to production host " + dst.ID + ".",
					}
					result.SolveTimeMs = time.Since(start).Milliseconds()
					return result, nil
				}
			}
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "No transitive SSH paths to production exist — no non-bastion relay can bridge to production."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// ProveFirewallMandatory checks that all private subnets route internet
// traffic through a Network Firewall endpoint. Returns UNSAT if all
// egress routes through firewall, SAT if a bypass exists.
func (g *Graph) ProveFirewallMandatory() (*ProofResult, error) {
	start := time.Now()

	privateSubnets := g.PrivateSubnets()
	if len(privateSubnets) == 0 {
		return nil, fmt.Errorf("%w: no subnets tagged stave:subnet-type=private", ErrVacuousProof)
	}
	if len(g.Firewalls) == 0 {
		return nil, fmt.Errorf("%w: no firewall endpoints found — cannot prove firewall routing", ErrVacuousProof)
	}

	result := &ProofResult{
		Property: "firewall-mandatory",
		Scope:    map[string]int{"private_subnets": len(privateSubnets), "firewall_endpoints": len(g.Firewalls)},
	}

	for _, sub := range privateSubnets {
		if sub.RouteTableID == "" {
			return nil, fmt.Errorf("%w: subnet %s has no route table association — cannot prove firewall routing", ErrVacuousProof, sub.ID)
		}
		for _, route := range g.Routes[sub.RouteTableID] {
			if route.Destination != "0.0.0.0/0" && route.Destination != "::/0" {
				continue
			}
			if route.TargetType == "igw" && !g.Firewalls[route.TargetID] {
				result.Result = "SAT"
				result.Interpretation = "Firewall bypass exists — private subnet routes internet traffic directly to an internet gateway."
				result.Counterexample = &Counterexample{
					Source:      sub.ID,
					Destination: route.TargetID,
					PathType:    "direct-igw",
					RuleSG:      sub.RouteTableID,
					RuleSource:  route.Destination,
					Explanation: "Subnet " + sub.ID + " has a " + route.Destination + " route to IGW " + route.TargetID + " in route table " + sub.RouteTableID + " without passing through a Network Firewall endpoint.",
					Remediation: "Change the " + route.Destination + " route in " + sub.RouteTableID + " to target a Network Firewall endpoint instead of " + route.TargetID + ".",
				}
				result.SolveTimeMs = time.Since(start).Milliseconds()
				return result, nil
			}
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "All private subnets route internet traffic through a Network Firewall endpoint."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// ProveTransitiveEgress checks that no isolated workload can transitively
// reach the internet via an intermediate host whose subnet has a NAT or
// IGW egress route. Returns UNSAT if no transitive path exists, SAT with
// a counterexample naming the relay host and port.
func (g *Graph) ProveTransitiveEgress() (*ProofResult, error) {
	start := time.Now()

	isolated := g.IsolatedHosts()
	if len(isolated) == 0 {
		return nil, fmt.Errorf("%w: no hosts tagged stave:network-zone=isolated", ErrVacuousProof)
	}

	// Build the set of hosts whose subnets have internet egress routes.
	type egressHost struct {
		host    *Host
		gateway string // target ID of the egress route (NAT or IGW)
	}
	var egress []egressHost
	for _, h := range g.allHosts() {
		if h.IsIsolated() {
			continue
		}
		sub := g.Subnets[h.SubnetID]
		if sub == nil || sub.RouteTableID == "" {
			continue
		}
		for _, route := range g.Routes[sub.RouteTableID] {
			if route.Destination != "0.0.0.0/0" && route.Destination != "::/0" {
				continue
			}
			if route.TargetType == "nat" || route.TargetType == "igw" {
				egress = append(egress, egressHost{host: h, gateway: route.TargetID})
				break
			}
		}
	}
	if len(egress) == 0 {
		return nil, fmt.Errorf("%w: no non-isolated hosts in subnets with internet egress routes", ErrVacuousProof)
	}

	result := &ProofResult{
		Property: "transitive-egress",
		Scope:    map[string]int{"isolated_hosts": len(isolated), "egress_hosts": len(egress)},
	}

	for _, iso := range isolated {
		for _, eg := range egress {
			ok, _, port := g.canReachAnyPort(iso.ID, eg.host.ID)
			if !ok {
				continue
			}
			result.Result = "SAT"
			result.Interpretation = "Transitive internet egress path exists — an isolated workload can reach a host with internet egress."
			result.Counterexample = &Counterexample{
				Source:      iso.ID,
				Destination: eg.host.ID,
				Port:        port,
				PathType:    "transitive-egress",
				Explanation: "Isolated host " + iso.ID + " can reach " + eg.host.ID + " on port " + strconv.Itoa(port) + ". " + eg.host.ID + "'s subnet routes 0.0.0.0/0 to " + eg.gateway + ". Two-hop path: " + iso.ID + " → " + eg.host.ID + " → internet.",
				Remediation: "Remove network access from " + iso.ID + " to " + eg.host.ID + ", or remove " + eg.host.ID + "'s internet egress route.",
			}
			result.SolveTimeMs = time.Since(start).Milliseconds()
			return result, nil
		}
	}

	result.Result = "UNSAT"
	result.Interpretation = "No isolated workload can transitively reach the internet via an intermediate host."
	result.SolveTimeMs = time.Since(start).Milliseconds()
	return result, nil
}
