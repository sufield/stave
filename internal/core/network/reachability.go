package network

import "fmt"

// RuleMatch is the authorization evidence for network reachability between hosts.
type RuleMatch struct {
	SecurityGroupID string
	RuleSource      string
	PathType        string
	Port            int
}

// newRuleMatch constructs a RuleMatch for authorized network reachability.
func newRuleMatch(securityGroupID, ruleSource, pathType string, port int) *RuleMatch {
	return &RuleMatch{
		SecurityGroupID: securityGroupID,
		RuleSource:      ruleSource,
		PathType:        pathType,
		Port:            port,
	}
}

// hostIdentity extracts the ID and VPC ID of a host, or empty strings if nil.
func hostIdentity(h *Host) (id string, vpcID string) {
	if h != nil {
		return h.SafeID(), h.VPCID
	}
	return "", ""
}

// Explanation formats the counterexample explanation describing why src can reach dst.
// Safe on nil receiver, src, or dst.
func (m *RuleMatch) Explanation(src, dst *Host) string {
	if m == nil {
		return ""
	}
	srcID, srcVPC := hostIdentity(src)
	dstID, dstVPC := hostIdentity(dst)
	switch m.PathType {
	case "external":
		return fmt.Sprintf("Production host %s accepts SSH from the internet (%s) on %s. No bastion in the path.",
			dstID, m.RuleSource, m.SecurityGroupID)
	case "cross-vpc":
		return fmt.Sprintf("Host %s (vpc:%s) can SSH to production host %s (vpc:%s) via VPC peering. Security group %s allows SSH from %s. No bastion in the path.",
			srcID, srcVPC, dstID, dstVPC, m.SecurityGroupID, m.RuleSource)
	default:
		return fmt.Sprintf("Host %s can SSH to production host %s via %s allowing SSH from %s. No bastion in the path.",
			srcID, dstID, m.SecurityGroupID, m.RuleSource)
	}
}

// Remediation formats the recommended corrective action to eliminate the bypass.
// Safe on nil receiver.
func (m *RuleMatch) Remediation(bastions []*Host) string {
	if m == nil {
		return ""
	}
	if m.PathType == "external" {
		return fmt.Sprintf("Remove SSH ingress from %s on %s. Restrict to bastion SG reference only.",
			m.RuleSource, m.SecurityGroupID)
	}
	rem := fmt.Sprintf("Remove SSH ingress rule (%s) on %s.", m.RuleSource, m.SecurityGroupID)
	if len(bastions) > 0 {
		rem += " Replace with SSH from bastion SG only."
	}
	return rem
}

// newSSHPath constructs an SSHPath describing an authorized network path.
func newSSHPath(source, destination string, port int, pathType, ruleSG, ruleSource string) SSHPath {
	return SSHPath{
		Source:      source,
		Destination: destination,
		Port:        port,
		PathType:    pathType,
		RuleSG:      ruleSG,
		RuleSource:  ruleSource,
	}
}

// SSHPath constructs an SSHPath from authorization evidence between source and destination.
// Safe on nil receiver.
func (m *RuleMatch) SSHPath(source, destination string) SSHPath {
	if m == nil {
		return newSSHPath(source, destination, 0, "", "", "")
	}
	return newSSHPath(source, destination, m.Port, m.PathType, m.SecurityGroupID, m.RuleSource)
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
	if g == nil {
		return nil
	}
	var paths []SSHPath
	for _, dst := range g.ProductionHosts() {
		paths = append(paths, g.enumerateHostSSHPaths(dst, port)...)
	}
	return paths
}

// enumerateHostSSHPaths finds all authorized internal and external SSH paths to dst.
// Safe on nil receiver or nil dst.
func (g *Graph) enumerateHostSSHPaths(dst *Host, port int) []SSHPath {
	if g == nil || dst == nil {
		return nil
	}
	paths := g.enumerateInternalSSHPaths(dst, port)
	paths = append(paths, g.enumerateExternalSSHPaths(dst, port)...)
	return paths
}

// findInternalSSHPath checks whether src can originate and reach dst on the given port.
// Returns the authorized SSHPath and true, or zero-value and false if not authorized.
// Safe on nil receiver, src, or dst.
func (g *Graph) findInternalSSHPath(src, dst *Host, port int) (SSHPath, bool) {
	if g == nil || !src.CanOriginateInternalSSHTo(dst) {
		return SSHPath{}, false
	}
	if match := g.Reachability(src, dst, port); match != nil {
		return match.SSHPath(src.ID, dst.ID), true
	}
	return SSHPath{}, false
}

// enumerateInternalSSHPaths finds all authorized SSH paths to dst from non-production internal hosts.
func (g *Graph) enumerateInternalSSHPaths(dst *Host, port int) []SSHPath {
	if g == nil || dst == nil {
		return nil
	}
	var paths []SSHPath
	for _, src := range g.allHosts() {
		if path, ok := g.findInternalSSHPath(src, dst, port); ok {
			paths = append(paths, path)
		}
	}
	return paths
}

// findExternalSSHPath converts an internet rule match on dst into an authorized external SSHPath.
// Safe on nil receiver, nil dst, or nil match.
func (g *Graph) findExternalSSHPath(dst *Host, match *RuleMatch) (SSHPath, bool) {
	if g == nil || dst == nil || match == nil {
		return SSHPath{}, false
	}
	return match.SSHPath(match.RuleSource, dst.ID), true
}

// enumerateExternalSSHPaths finds all direct public internet SSH ingress paths to dst.
func (g *Graph) enumerateExternalSSHPaths(dst *Host, port int) []SSHPath {
	if g == nil || dst == nil {
		return nil
	}
	var paths []SSHPath
	for _, match := range g.findInternetRulesMatching(dst, func(r SGRule) bool { return r.IsInternetIngressOnPort(port) }) {
		if path, ok := g.findExternalSSHPath(dst, match); ok {
			paths = append(paths, path)
		}
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
				return newRuleMatch(dstSG, rule.RuleSource(), pathType, rule.Port)
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
				matches = append(matches, newRuleMatch(dstSG, rule.SourceValue, "external", rule.Port))
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
