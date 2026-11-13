package network

import (
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
)

// Host is a compute resource with network placement.
type Host struct {
	ID        string
	VPCID     string
	SubnetID  string
	SGIDs     []string
	PrivateIP string
	PublicIP  string
	Tags      map[string]string
}

// Environment returns the host's environment tag value, or "" if untagged or receiver is nil.
func (h *Host) Environment() string {
	if h == nil {
		return ""
	}
	return h.Tags["stave:environment"]
}

func (h *Host) IsProduction() bool   { return h.Environment() == "production" }
func (h *Host) IsBastion() bool      { return h != nil && h.Tags["stave:role"] == "bastion" }
func (h *Host) IsDevelopment() bool  { return h.Environment() == "development" }
func (h *Host) IsDatabaseTier() bool { return h.Tags["stave:tier"] == "database" }
func (h *Host) IsIsolated() bool     { return h.Tags["stave:network-zone"] == "isolated" }

// IsCrossVPC reports whether both hosts are assigned to VPCs and reside in different VPCs.
func (h *Host) IsCrossVPC(other *Host) bool {
	return h != nil && other != nil && h.VPCID != "" && other.VPCID != "" && h.VPCID != other.VPCID
}

// SameVPC reports whether both hosts are assigned to the same non-empty VPC.
// Safe on nil receiver.
func (h *Host) SameVPC(other *Host) bool {
	return h != nil && other != nil && h.VPCID != "" && h.VPCID == other.VPCID
}

// SameHost reports whether both hosts represent the same compute resource.
// Safe on nil receiver.
func (h *Host) SameHost(other *Host) bool {
	return h != nil && other != nil && h.ID != "" && h.ID == other.ID
}

// IsInternal reports whether other is within the same internal network scope
// (i.e., represents the same compute host or resides in the same non-empty VPC).
// Safe on nil receiver.
func (h *Host) IsInternal(other *Host) bool {
	return h.SameHost(other) || h.SameVPC(other)
}

// IsTrusted reports whether h is trusted in the context of the specified target hosts
// (i.e. represents the same compute host as any target via local boundary, resides
// in the production environment via operational trust, or is an authorized bastion).
// Safe on nil receiver and nil targets.
func (h *Host) IsTrusted(targets ...*Host) bool {
	if h == nil {
		return false
	}
	if h.IsProduction() || h.IsBastion() {
		return true
	}
	for _, target := range targets {
		if h.SameHost(target) {
			return true
		}
	}
	return false
}

// HasSecurityGroup reports whether h is associated with the specified security group ID.
// Safe on nil receiver.
func (h *Host) HasSecurityGroup(sgID string) bool {
	if h == nil || sgID == "" {
		return false
	}
	return slices.Contains(h.SGIDs, sgID)
}

// SGRule is a single security group rule.
type SGRule struct {
	Direction   string // "ingress" | "egress"
	Protocol    string
	Port        int
	SourceType  string // "cidr" | "sg"
	SourceValue string
}

// IsIngress reports whether the security group rule applies to inbound traffic.
func (r SGRule) IsIngress() bool {
	return r.Direction == "ingress"
}

// IsCIDR reports whether the security group rule source is a CIDR block.
func (r SGRule) IsCIDR() bool {
	return r.SourceType == "cidr"
}

// IsSecurityGroup reports whether the security group rule source is another security group.
func (r SGRule) IsSecurityGroup() bool {
	return r.SourceType == "sg"
}

// HasBroadInternalCIDR reports whether the security group rule source is a broad
// internal CIDR block (RFC1918 range or 0.0.0.0/0 / ::/0).
func (r SGRule) HasBroadInternalCIDR() bool {
	return r.IsCIDR() && broadInternalCIDRs[r.SourceValue]
}

// IsInternetIngress reports whether the security group rule permits inbound
// traffic from the public internet ("0.0.0.0/0" or "::/0").
func (r SGRule) IsInternetIngress() bool {
	return r.IsIngress() && r.IsCIDR() && (r.SourceValue == "0.0.0.0/0" || r.SourceValue == "::/0")
}

// IsInternetIngressOnPort reports whether the security group rule permits inbound
// traffic from the public internet on the specified port.
func (r SGRule) IsInternetIngressOnPort(port int) bool {
	return r.Port == port && r.IsInternetIngress()
}

// IsIngressOnPort reports whether the security group rule permits inbound
// traffic on the specified port.
func (r SGRule) IsIngressOnPort(port int) bool {
	return r.Port == port && r.IsIngress()
}

// RuleSource returns the formatted source identifier (e.g. "sg:sg-12345" or "cidr:10.0.0.0/8").
func (r SGRule) RuleSource() string {
	if r.SourceType != "" {
		return r.SourceType + ":" + r.SourceValue
	}
	return r.SourceValue
}

// IsInternal reports whether the security group rule permits internal access
// from src to dst (either logically via security group reference or via
// perimeter-level broad CIDR within the same VPC), returning true and the
// corresponding path type ("sg-ref" or "cidr").
// Safe on nil src and dst.
func (r SGRule) IsInternal(src, dst *Host) (bool, string) {
	if r.IsSecurityGroup() && src.HasSecurityGroup(r.SourceValue) {
		return true, "sg-ref"
	}
	if r.HasBroadInternalCIDR() && src.SameVPC(dst) {
		return true, "cidr"
	}
	return false, ""
}

// VPCPeering is a VPC peering connection.
type VPCPeering struct {
	PeeringID    string
	RequesterVPC string
	AccepterVPC  string
}

// Connects reports whether this peering connection connects the two specified
// VPCs in either direction. Returns false if either VPC ID is empty.
func (p VPCPeering) Connects(vpc1, vpc2 string) bool {
	if vpc1 == "" || vpc2 == "" {
		return false
	}
	return (p.RequesterVPC == vpc1 && p.AccepterVPC == vpc2) ||
		(p.RequesterVPC == vpc2 && p.AccepterVPC == vpc1)
}

// Subnet is a VPC subnet with route table association.
type Subnet struct {
	ID           string
	VPCID        string
	RouteTableID string
	Tags         map[string]string
}

// IsPrivate returns true if the subnet is tagged stave:subnet-type=private.
func (s *Subnet) IsPrivate() bool { return s.Tags["stave:subnet-type"] == "private" }

// HasRouteTable reports whether the subnet is associated with a route table.
// Safe on nil receiver.
func (s *Subnet) HasRouteTable() bool {
	return s != nil && s.RouteTableID != ""
}

// Route is a single route in a route table.
type Route struct {
	Destination string // "0.0.0.0/0", "::/0", etc.
	TargetType  string // "igw", "vpce", "nat", "local"
	TargetID    string
}

// IsDefaultRoute reports whether the route destination covers all IPv4
// ("0.0.0.0/0") or IPv6 ("::/0") addresses.
func (r Route) IsDefaultRoute() bool {
	return r.Destination == "0.0.0.0/0" || r.Destination == "::/0"
}

// IsInternetGateway reports whether the route target is an internet gateway ("igw").
func (r Route) IsInternetGateway() bool {
	return r.TargetType == "igw"
}

// Target returns the formatted route target string (e.g. "nat:nat-01", "igw:igw-01").
func (r Route) Target() string {
	if r.TargetType == "" && r.TargetID == "" {
		return ""
	}
	if r.TargetID == "" {
		return r.TargetType
	}
	return r.TargetType + ":" + r.TargetID
}

// TGWAttachment is a Transit Gateway VPC attachment.
type TGWAttachment struct {
	AttachmentID     string
	TransitGatewayID string
	VPCID            string
}

// Graph is the network topology extracted from observations.
type Graph struct {
	Hosts          map[string]*Host
	SGRules        map[string][]SGRule // sg_id -> rules
	Peerings       []VPCPeering
	Subnets        map[string]*Subnet
	Routes         map[string][]Route // route_table_id -> routes
	Firewalls      map[string]bool    // firewall endpoint IDs
	TGWAttachments []TGWAttachment
}

// BuildGraph extracts network topology from observation snapshots.
func BuildGraph(snapshots []asset.Snapshot) *Graph {
	g := &Graph{
		Hosts:     make(map[string]*Host),
		SGRules:   make(map[string][]SGRule),
		Subnets:   make(map[string]*Subnet),
		Routes:    make(map[string][]Route),
		Firewalls: make(map[string]bool),
	}
	if GraphTypes.Instance == "" {
		return g
	}
	for i := range snapshots {
		for j := range snapshots[i].Assets {
			a := &snapshots[i].Assets[j] //nolint:gosec // index is within range
			switch string(a.Type) {
			case GraphTypes.Instance:
				g.extractHost(a)
			case GraphTypes.SecurityGroup:
				g.extractSGRules(a)
			case GraphTypes.PeeringConnection:
				g.extractPeering(a)
			case GraphTypes.Subnet:
				if GraphTypes.Subnet != "" {
					g.extractSubnet(a)
				}
			case GraphTypes.RouteTable:
				if GraphTypes.RouteTable != "" {
					g.extractRouteTable(a)
				}
			case GraphTypes.Firewall:
				if GraphTypes.Firewall != "" {
					g.extractFirewall(a)
				}
			case GraphTypes.TransitGateway:
				if GraphTypes.TransitGateway != "" {
					g.extractTGWAttachment(a)
				}
			}
		}
	}
	return g
}

func (g *Graph) extractHost(a *asset.Asset) {
	h := &Host{
		ID:   string(a.ID),
		Tags: make(map[string]string),
	}
	if compute, ok := nested(a.Properties, "compute", "instance"); ok {
		h.VPCID, _ = compute["vpc_id"].(string)
		h.SubnetID, _ = compute["subnet_id"].(string)
		h.PrivateIP, _ = compute["private_ip"].(string)
		h.PublicIP, _ = compute["public_ip"].(string)
		if sgs, ok := compute["security_groups"].([]any); ok {
			for _, sg := range sgs {
				if s, ok := sg.(string); ok {
					h.SGIDs = append(h.SGIDs, s)
				}
			}
		}
	}
	if tags, ok := a.Properties["tags"].(map[string]any); ok {
		for k, v := range tags {
			if s, ok := v.(string); ok {
				h.Tags[k] = strings.ToLower(s)
			}
		}
	}
	g.Hosts[h.ID] = h
}

func (g *Graph) extractSGRules(a *asset.Asset) {
	sgID := string(a.ID)
	if sg, ok := nested(a.Properties, "network", "security_group"); ok {
		if rules, ok := sg["rules"].([]any); ok {
			for _, r := range rules {
				rm, ok := r.(map[string]any)
				if !ok {
					continue
				}
				rule := SGRule{
					Protocol: "tcp",
				}
				rule.Direction, _ = rm["direction"].(string)
				rule.Protocol, _ = rm["protocol"].(string)
				rule.SourceType, _ = rm["source_type"].(string)
				rule.SourceValue, _ = rm["source_value"].(string)
				if p, ok := rm["from_port"].(float64); ok {
					rule.Port = int(p)
				}
				g.SGRules[sgID] = append(g.SGRules[sgID], rule)
			}
		}
	}
}

func (g *Graph) extractPeering(a *asset.Asset) {
	p := VPCPeering{PeeringID: string(a.ID)}
	if net, ok := nested(a.Properties, "network", "peering"); ok {
		p.RequesterVPC, _ = net["requester_vpc"].(string)
		p.AccepterVPC, _ = net["accepter_vpc"].(string)
	}
	g.Peerings = append(g.Peerings, p)
}

// nested navigates a property map by keys, returning the final map.
func nested(props map[string]any, keys ...string) (map[string]any, bool) {
	m := props
	for _, k := range keys {
		next, ok := m[k].(map[string]any)
		if !ok {
			return nil, false
		}
		m = next
	}
	return m, true
}

// ProductionHosts returns all hosts tagged stave:environment=production.
func (g *Graph) ProductionHosts() []*Host {
	var out []*Host
	for _, h := range g.Hosts {
		if h.IsProduction() {
			out = append(out, h)
		}
	}
	return out
}

// BastionHosts returns all hosts tagged stave:role=bastion.
func (g *Graph) BastionHosts() []*Host {
	var out []*Host
	for _, h := range g.Hosts {
		if h.IsBastion() {
			out = append(out, h)
		}
	}
	return out
}

// DevelopmentHosts returns all hosts tagged stave:environment=development.
func (g *Graph) DevelopmentHosts() []*Host {
	var out []*Host
	for _, h := range g.Hosts {
		if h.IsDevelopment() {
			out = append(out, h)
		}
	}
	return out
}

// DatabaseHosts returns all hosts tagged stave:tier=database.
func (g *Graph) DatabaseHosts() []*Host {
	var out []*Host
	for _, h := range g.Hosts {
		if h.IsDatabaseTier() {
			out = append(out, h)
		}
	}
	return out
}

// IsolatedHosts returns all hosts tagged stave:network-zone=isolated.
func (g *Graph) IsolatedHosts() []*Host {
	var out []*Host
	for _, h := range g.Hosts {
		if h.IsIsolated() {
			out = append(out, h)
		}
	}
	return out
}

// PrivateSubnets returns all subnets tagged stave:subnet-type=private.
func (g *Graph) PrivateSubnets() []*Subnet {
	var out []*Subnet
	for _, s := range g.Subnets {
		if s.IsPrivate() {
			out = append(out, s)
		}
	}
	return out
}

// SubnetForHost returns the subnet associated with the given host.
// Safe on nil receiver or nil host.
func (g *Graph) SubnetForHost(h *Host) *Subnet {
	if g == nil || h == nil || h.SubnetID == "" {
		return nil
	}
	return g.Subnets[h.SubnetID]
}

// RoutesForSubnet returns all routes associated with the subnet's route table.
// Safe on nil receiver or nil subnet.
func (g *Graph) RoutesForSubnet(sub *Subnet) []Route {
	if g == nil || !sub.HasRouteTable() {
		return nil
	}
	return g.Routes[sub.RouteTableID]
}

func (g *Graph) extractSubnet(a *asset.Asset) {
	s := &Subnet{
		ID:   string(a.ID),
		Tags: make(map[string]string),
	}
	if net, ok := nested(a.Properties, "network", "subnet"); ok {
		s.VPCID, _ = net["vpc_id"].(string)
		s.RouteTableID, _ = net["route_table_id"].(string)
	}
	if tags, ok := a.Properties["tags"].(map[string]any); ok {
		for k, v := range tags {
			if sv, ok := v.(string); ok {
				s.Tags[k] = strings.ToLower(sv)
			}
		}
	}
	g.Subnets[s.ID] = s
}

func (g *Graph) extractRouteTable(a *asset.Asset) {
	rtID := string(a.ID)
	if rt, ok := nested(a.Properties, "network", "route_table"); ok {
		if routes, ok := rt["routes"].([]any); ok {
			for _, r := range routes {
				rm, ok := r.(map[string]any)
				if !ok {
					continue
				}
				route := Route{}
				route.Destination, _ = rm["destination"].(string)
				route.TargetType, _ = rm["target_type"].(string)
				route.TargetType = strings.ToLower(route.TargetType)
				route.TargetID, _ = rm["target_id"].(string)
				g.Routes[rtID] = append(g.Routes[rtID], route)
			}
		}
	}
}

func (g *Graph) extractFirewall(a *asset.Asset) {
	if fw, ok := nested(a.Properties, "network", "firewall"); ok {
		if endpoints, ok := fw["endpoints"].([]any); ok {
			for _, ep := range endpoints {
				if epID, ok := ep.(string); ok {
					g.Firewalls[epID] = true
				}
			}
		}
	}
}

func (g *Graph) extractTGWAttachment(a *asset.Asset) {
	if tgw, ok := nested(a.Properties, "network", "transit_gateway"); ok {
		att := TGWAttachment{AttachmentID: string(a.ID)}
		att.TransitGatewayID, _ = tgw["transit_gateway_id"].(string)
		att.VPCID, _ = tgw["vpc_id"].(string)
		g.TGWAttachments = append(g.TGWAttachments, att)
	}
}

// VPCsConnected reports whether two distinct VPCs are connected via VPC peering
// or Transit Gateway. Safe on nil receiver. Returns false if either VPC ID is empty.
func (g *Graph) VPCsConnected(vpc1, vpc2 string) bool {
	if g == nil || vpc1 == "" || vpc2 == "" {
		return false
	}
	return g.vpcsArePeered(vpc1, vpc2) || g.vpcsConnectedViaTGW(vpc1, vpc2)
}

// CanRouteCrossVPC reports whether src and dst reside in different VPCs and their
// respective VPCs are connected via VPC peering or Transit Gateway.
// Safe on nil receiver, src, or dst.
func (g *Graph) CanRouteCrossVPC(src, dst *Host) bool {
	return g != nil && src.IsCrossVPC(dst) && g.VPCsConnected(src.VPCID, dst.VPCID)
}

func (g *Graph) vpcsArePeered(vpc1, vpc2 string) bool {
	if g == nil {
		return false
	}
	for _, p := range g.Peerings {
		if p.Connects(vpc1, vpc2) {
			return true
		}
	}
	return false
}

func (g *Graph) vpcsConnectedViaTGW(vpc1, vpc2 string) bool {
	if g == nil || vpc1 == "" || vpc2 == "" {
		return false
	}
	tgws := make(map[string][]string)
	for _, att := range g.TGWAttachments {
		tgws[att.TransitGatewayID] = append(tgws[att.TransitGatewayID], att.VPCID)
	}
	for _, vpcs := range tgws {
		if slices.Contains(vpcs, vpc1) && slices.Contains(vpcs, vpc2) {
			return true
		}
	}
	return false
}
