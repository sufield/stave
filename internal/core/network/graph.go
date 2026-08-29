package network

import (
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

func (h *Host) IsProduction() bool   { return h.Tags["stave:environment"] == "production" }
func (h *Host) IsBastion() bool      { return h.Tags["stave:role"] == "bastion" }
func (h *Host) IsDevelopment() bool  { return h.Tags["stave:environment"] == "development" }
func (h *Host) IsDatabaseTier() bool { return h.Tags["stave:tier"] == "database" }
func (h *Host) IsIsolated() bool     { return h.Tags["stave:network-zone"] == "isolated" }

// SGRule is a single security group rule.
type SGRule struct {
	Direction   string // "ingress" | "egress"
	Protocol    string
	Port        int
	SourceType  string // "cidr" | "sg"
	SourceValue string
}

// VPCPeering is a VPC peering connection.
type VPCPeering struct {
	PeeringID    string
	RequesterVPC string
	AccepterVPC  string
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

// Route is a single route in a route table.
type Route struct {
	Destination string // "0.0.0.0/0", "::/0", etc.
	TargetType  string // "igw", "vpce", "nat", "local"
	TargetID    string
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

func (g *Graph) vpcsConnectedViaTGW(vpc1, vpc2 string) bool {
	tgws := make(map[string][]string)
	for _, att := range g.TGWAttachments {
		tgws[att.TransitGatewayID] = append(tgws[att.TransitGatewayID], att.VPCID)
	}
	for _, vpcs := range tgws {
		has1, has2 := false, false
		for _, v := range vpcs {
			if v == vpc1 {
				has1 = true
			}
			if v == vpc2 {
				has2 = true
			}
		}
		if has1 && has2 {
			return true
		}
	}
	return false
}
