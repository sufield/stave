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
func (g *Graph) CanReach(srcID, dstID string, port int) (bool, string) {
	src, ok := g.Hosts[srcID]
	if !ok {
		return false, ""
	}
	dst, ok := g.Hosts[dstID]
	if !ok {
		return false, ""
	}

	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if !rule.IsIngress() || rule.Port != port {
				continue
			}
			if ok, pathType := rule.IsInternal(src, dst); ok {
				return true, pathType
			}
		}
	}

	// Cross-VPC via peering or transit gateway.
	if g.CanRouteCrossVPC(src, dst) {
		for _, dstSG := range dst.SGIDs {
			for _, rule := range g.SGRules[dstSG] {
				if !rule.IsIngress() || rule.Port != port {
					continue
				}
				if rule.HasBroadInternalCIDR() {
					return true, "cross-vpc"
				}
			}
		}
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
			if ok, pathType := g.CanReach(src.ID, dst.ID, port); ok {
				ruleSG, ruleSource := g.findRule(src, dst, port)
				paths = append(paths, SSHPath{
					Source:      src.ID,
					Destination: dst.ID,
					Port:        port,
					PathType:    pathType,
					RuleSG:      ruleSG,
					RuleSource:  ruleSource,
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

// canReachAnyPort reports whether src can reach dst on any port via SG rules.
// Returns the path type and matched port.
func (g *Graph) canReachAnyPort(srcID, dstID string) (bool, string, int) {
	src, ok := g.Hosts[srcID]
	if !ok {
		return false, "", 0
	}
	dst, ok := g.Hosts[dstID]
	if !ok {
		return false, "", 0
	}

	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if !rule.IsIngress() {
				continue
			}
			if ok, pathType := rule.IsInternal(src, dst); ok {
				return true, pathType, rule.Port
			}
		}
	}

	if g.CanRouteCrossVPC(src, dst) {
		for _, dstSG := range dst.SGIDs {
			for _, rule := range g.SGRules[dstSG] {
				if !rule.IsIngress() {
					continue
				}
				if rule.HasBroadInternalCIDR() {
					return true, "cross-vpc", rule.Port
				}
			}
		}
	}

	return false, "", 0
}

func (g *Graph) allHosts() []*Host {
	out := make([]*Host, 0, len(g.Hosts))
	for _, h := range g.Hosts {
		out = append(out, h)
	}
	return out
}

func (g *Graph) findRule(src, dst *Host, port int) (string, string) {
	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if !rule.IsIngress() || rule.Port != port {
				continue
			}
			if rule.IsSecurityGroup() && src.HasSecurityGroup(rule.SourceValue) {
				return dstSG, "sg:" + rule.SourceValue
			}
			if rule.HasBroadInternalCIDR() {
				return dstSG, "cidr:" + rule.SourceValue
			}
		}
	}
	return "", ""
}
