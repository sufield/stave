package network

// SSHPath describes a network path to a host on port 22.
type SSHPath struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	PathType    string `json:"path_type"` // "sg-ref" | "cidr" | "cross-vpc"
	RuleSG      string `json:"rule_sg"`
	RuleSource  string `json:"rule_source"`
}

// RuleMatch is the authorization evidence for network reachability between hosts.
type RuleMatch struct {
	SecurityGroupID string
	RuleSource      string
	PathType        string
	Port            int
}

// Explanation formats the counterexample explanation describing why src can reach dst.
// Safe on nil receiver, src, or dst.
func (m *RuleMatch) Explanation(src, dst *Host) string {
	if m == nil {
		return ""
	}
	srcID, srcVPC := "", ""
	if src != nil {
		srcID = src.ID
		srcVPC = src.VPCID
	}
	dstID, dstVPC := "", ""
	if dst != nil {
		dstID = dst.ID
		dstVPC = dst.VPCID
	}
	switch m.PathType {
	case "external":
		return "Production host " + dstID + " accepts SSH from the internet (" + m.RuleSource + ") on " + m.SecurityGroupID + ". No bastion in the path."
	case "cross-vpc":
		return "Host " + srcID + " (vpc:" + srcVPC + ") can SSH to production host " +
			dstID + " (vpc:" + dstVPC + ") via VPC peering. Security group " +
			m.SecurityGroupID + " allows SSH from " + m.RuleSource + ". No bastion in the path."
	default:
		return "Host " + srcID + " can SSH to production host " +
			dstID + " via " + m.SecurityGroupID + " allowing SSH from " + m.RuleSource + ". No bastion in the path."
	}
}

// Remediation formats the recommended corrective action to eliminate the bypass.
// Safe on nil receiver.
func (m *RuleMatch) Remediation(bastions []*Host) string {
	if m == nil {
		return ""
	}
	if m.PathType == "external" {
		return "Remove SSH ingress from " + m.RuleSource + " on " + m.SecurityGroupID + ". Restrict to bastion SG reference only."
	}
	rem := "Remove SSH ingress rule (" + m.RuleSource + ") on " + m.SecurityGroupID + "."
	if len(bastions) > 0 {
		rem += " Replace with SSH from bastion SG only."
	}
	return rem
}

// broadInternalCIDRs are CIDRs that cover entire RFC1918 ranges.
// Soufflé can't do CIDR math; we match the same set here.
var broadInternalCIDRs = map[string]bool{
	"10.0.0.0/8":     true,
	"172.16.0.0/12":  true,
	"192.168.0.0/16": true,
	"0.0.0.0/0":      true,
	"::/0":           true,
}

// CanReach reports whether src can reach dst on the given port via SG rules.
// Safe on nil receiver, src, or dst.
func (g *Graph) CanReach(src, dst *Host, port int) (bool, string) {
	if match := g.findRule(src, dst, port); match != nil {
		return true, match.PathType
	}
	return false, ""
}

// EnumerateSSHPaths finds all SSH paths to production hosts.
func (g *Graph) EnumerateSSHPaths(port int) []SSHPath {
	prod := g.ProductionHosts()
	var paths []SSHPath

	for _, dst := range prod {
		for _, src := range g.allHosts() {
			if src.SameHost(dst) {
				continue
			}
			if src.IsProduction() {
				continue
			}
			if match := g.findRule(src, dst, port); match != nil {
				paths = append(paths, SSHPath{
					Source:      src.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    match.PathType,
					RuleSG:      match.SecurityGroupID,
					RuleSource:  match.RuleSource,
				})
			}
		}

		// External entry (0.0.0.0/0).
		for _, dstSG := range dst.SGIDs {
			for _, rule := range g.SGRules[dstSG] {
				if rule.IsInternetIngressOnPort(port) {
					paths = append(paths, SSHPath{
						Source:      "0.0.0.0/0",
						Destination: dst.ID,
						Port:        port,
						PathType:    "external",
						RuleSG:      dstSG,
						RuleSource:  "0.0.0.0/0",
					})
				}
			}
		}
	}
	return paths
}

func (g *Graph) allHosts() []*Host {
	out := make([]*Host, 0, len(g.Hosts))
	for _, h := range g.Hosts {
		out = append(out, h)
	}
	return out
}

// findRule finds the security group rule authorizing traffic from src to dst on the given port.
// Safe on nil receiver, src, or dst.
func (g *Graph) findRule(src, dst *Host, port int) *RuleMatch {
	if g == nil || src == nil || dst == nil {
		return nil
	}

	canCrossVPC := g.CanRouteCrossVPC(src, dst)
	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if !rule.IsIngressOnPort(port) {
				continue
			}
			if ok, pathType := rule.Allows(src, dst, canCrossVPC); ok {
				return &RuleMatch{
					SecurityGroupID: dstSG,
					RuleSource:      rule.RuleSource(),
					PathType:        pathType,
					Port:            port,
				}
			}
		}
	}
	return nil
}

// findRuleAnyPort finds a security group rule authorizing traffic from src to dst on any port.
// Safe on nil receiver, src, or dst.
func (g *Graph) findRuleAnyPort(src, dst *Host) *RuleMatch {
	if g == nil || src == nil || dst == nil {
		return nil
	}

	canCrossVPC := g.CanRouteCrossVPC(src, dst)
	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if !rule.IsIngress() {
				continue
			}
			if ok, pathType := rule.Allows(src, dst, canCrossVPC); ok {
				return &RuleMatch{
					SecurityGroupID: dstSG,
					RuleSource:      rule.RuleSource(),
					PathType:        pathType,
					Port:            rule.Port,
				}
			}
		}
	}
	return nil
}

// findInternetRule finds the security group rule authorizing public internet ingress to dst on the given port.
// Safe on nil receiver or nil dst.
func (g *Graph) findInternetRule(dst *Host, port int) *RuleMatch {
	if g == nil || dst == nil {
		return nil
	}

	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if rule.IsInternetIngressOnPort(port) {
				return &RuleMatch{
					SecurityGroupID: dstSG,
					RuleSource:      rule.SourceValue,
					PathType:        "external",
					Port:            port,
				}
			}
		}
	}
	return nil
}

// findInternetRuleAnyPort finds a security group rule authorizing public internet ingress to dst on any port.
// Safe on nil receiver or nil dst.
func (g *Graph) findInternetRuleAnyPort(dst *Host) *RuleMatch {
	if g == nil || dst == nil {
		return nil
	}

	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if rule.IsInternetIngress() {
				return &RuleMatch{
					SecurityGroupID: dstSG,
					RuleSource:      rule.SourceValue,
					PathType:        "external",
					Port:            rule.Port,
				}
			}
		}
	}
	return nil
}
