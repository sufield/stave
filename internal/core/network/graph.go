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

func (h *Host) IsProduction() bool { return h.Tags["stave:environment"] == "production" }
func (h *Host) IsBastion() bool    { return h.Tags["stave:role"] == "bastion" }

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

// Graph is the network topology extracted from observations.
type Graph struct {
	Hosts    map[string]*Host
	SGRules  map[string][]SGRule // sg_id -> rules
	Peerings []VPCPeering
}

// BuildGraph extracts network topology from observation snapshots.
func BuildGraph(snapshots []asset.Snapshot) *Graph {
	g := &Graph{
		Hosts:   make(map[string]*Host),
		SGRules: make(map[string][]SGRule),
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
