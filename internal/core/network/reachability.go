package network

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

// SSHPath constructs an SSHPath from authorization evidence between source and destination.
// Safe on nil receiver.
func (m *RuleMatch) SSHPath(source, destination string) SSHPath {
	if m == nil {
		return SSHPath{Source: source, Destination: destination}
	}
	return SSHPath{
		Source:      source,
		Destination: destination,
		Port:        m.Port,
		PathType:    m.PathType,
		RuleSG:      m.SecurityGroupID,
		RuleSource:  m.RuleSource,
	}
}

// Reachability reports authorization evidence for traffic from src to dst on the given port.
// Returns a RuleMatch with security group and path details, or nil if traffic is not authorized.
// Safe on nil receiver, src, or dst.
func (g *Graph) Reachability(src, dst *Host, port int) *RuleMatch {
	return g.findRuleMatching(src, dst, func(r SGRule) bool { return r.IsIngressOnPort(port) })
}

// ReachabilityAnyPort reports authorization evidence for traffic from src to dst on any port.
// Returns a RuleMatch with security group and path details, or nil if no traffic is authorized.
// Safe on nil receiver, src, or dst.
func (g *Graph) ReachabilityAnyPort(src, dst *Host) *RuleMatch {
	return g.findRuleMatching(src, dst, SGRule.IsIngress)
}

// CanReach reports whether src can reach dst on the given port via SG rules.
// Safe on nil receiver, src, or dst.
func (g *Graph) CanReach(src, dst *Host, port int) (bool, string) {
	if match := g.Reachability(src, dst, port); match != nil {
		return true, match.PathType
	}
	return false, ""
}

// EnumerateSSHPaths finds all SSH paths to production hosts.
func (g *Graph) EnumerateSSHPaths(port int) []SSHPath {
	var paths []SSHPath
	for _, dst := range g.ProductionHosts() {
		paths = append(paths, g.enumerateInternalSSHPaths(dst, port)...)
		paths = append(paths, g.enumerateExternalSSHPaths(dst, port)...)
	}
	return paths
}

// enumerateInternalSSHPaths finds all authorized SSH paths to dst from non-production internal hosts.
func (g *Graph) enumerateInternalSSHPaths(dst *Host, port int) []SSHPath {
	var paths []SSHPath
	for _, src := range g.allHosts() {
		if src.SameHost(dst) || src.IsProduction() {
			continue
		}
		if match := g.Reachability(src, dst, port); match != nil {
			paths = append(paths, match.SSHPath(src.ID, dst.ID))
		}
	}
	return paths
}

// enumerateExternalSSHPaths finds all direct public internet SSH ingress paths to dst.
func (g *Graph) enumerateExternalSSHPaths(dst *Host, port int) []SSHPath {
	var paths []SSHPath
	for _, match := range g.findInternetRulesMatching(dst, func(r SGRule) bool { return r.IsInternetIngressOnPort(port) }) {
		paths = append(paths, match.SSHPath(match.RuleSource, dst.ID))
	}
	return paths
}

func (g *Graph) findRuleMatching(src, dst *Host, filter func(SGRule) bool) *RuleMatch {
	if g == nil || src == nil || dst == nil {
		return nil
	}

	canCrossVPC := g.CanRouteCrossVPC(src, dst)
	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if !filter(rule) {
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

func (g *Graph) findInternetRulesMatching(dst *Host, filter func(SGRule) bool) []*RuleMatch {
	if g == nil || dst == nil {
		return nil
	}

	var matches []*RuleMatch
	for _, dstSG := range dst.SGIDs {
		for _, rule := range g.SGRules[dstSG] {
			if filter(rule) {
				matches = append(matches, &RuleMatch{
					SecurityGroupID: dstSG,
					RuleSource:      rule.SourceValue,
					PathType:        "external",
					Port:            rule.Port,
				})
			}
		}
	}
	return matches
}

func (g *Graph) findInternetRuleMatching(dst *Host, filter func(SGRule) bool) *RuleMatch {
	matches := g.findInternetRulesMatching(dst, filter)
	if len(matches) > 0 {
		return matches[0]
	}
	return nil
}

// findInternetRule finds the security group rule authorizing public internet ingress to dst on the given port.
// Safe on nil receiver or nil dst.
func (g *Graph) findInternetRule(dst *Host, port int) *RuleMatch {
	return g.findInternetRuleMatching(dst, func(r SGRule) bool { return r.IsInternetIngressOnPort(port) })
}

// findInternetRuleAnyPort finds a security group rule authorizing public internet ingress to dst on any port.
// Safe on nil receiver or nil dst.
func (g *Graph) findInternetRuleAnyPort(dst *Host) *RuleMatch {
	return g.findInternetRuleMatching(dst, SGRule.IsInternetIngress)
}

// IsPubliclyAccessible reports whether h is accessible from the public internet
// on the specified port.
// Safe on nil receiver or nil host.
func (g *Graph) IsPubliclyAccessible(h *Host, port int) bool {
	return g.findInternetRule(h, port) != nil
}
