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

// SafeID returns the host's ID, or an empty string if receiver is nil.
func (h *Host) SafeID() string {
	if h == nil {
		return ""
	}
	return h.ID
}

// Tag returns the tag value for key, or an empty string if untagged or receiver is nil.
func (h *Host) Tag(key string) string {
	if h == nil {
		return ""
	}
	return h.Tags[key]
}

// Environment returns the host's environment tag value, or "" if untagged or receiver is nil.
func (h *Host) Environment() string {
	return h.Tag("stave:environment")
}

func (h *Host) IsProduction() bool   { return h.Environment() == "production" }
func (h *Host) IsBastion() bool      { return h.Tag("stave:role") == "bastion" }
func (h *Host) IsDevelopment() bool  { return h.Environment() == "development" }
func (h *Host) IsDatabaseTier() bool { return h.Tag("stave:tier") == "database" }
func (h *Host) IsIsolated() bool     { return h.Tag("stave:network-zone") == "isolated" }

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
	return slices.ContainsFunc(targets, h.SameHost)
}

// CanOriginateInternalSSHTo reports whether h is eligible to originate internal SSH
// to the destination host (i.e. is non-nil, distinct from dst, and not a production host).
// Safe on nil receiver or nil dst.
func (h *Host) CanOriginateInternalSSHTo(dst *Host) bool {
	if h == nil || h.SameHost(dst) || h.IsProduction() {
		return false
	}
	return true
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

// broadInternalCIDRs are CIDRs that cover entire RFC1918 ranges.
// Soufflé can't do CIDR math; we match the same set here.
var broadInternalCIDRs = map[string]bool{
	"10.0.0.0/8":     true,
	"172.16.0.0/12":  true,
	"192.168.0.0/16": true,
	"0.0.0.0/0":      true,
	"::/0":           true,
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

// MatchesPort reports whether the security group rule matches the specified port.
func (r SGRule) MatchesPort(port int) bool {
	return r.Port == port
}

// IsInternetIngressOnPort reports whether the security group rule permits inbound
// traffic from the public internet on the specified port.
func (r SGRule) IsInternetIngressOnPort(port int) bool {
	return r.MatchesPort(port) && r.IsInternetIngress()
}

// IsIngressOnPort reports whether the security group rule permits inbound
// traffic on the specified port.
func (r SGRule) IsIngressOnPort(port int) bool {
	return r.MatchesPort(port) && r.IsIngress()
}

// formatPrefixed formats an identifier with an optional type prefix (e.g. "prefix:value").
// If either prefix or value is empty, the non-empty part is returned without a colon separator.
func formatPrefixed(prefix, value string) string {
	if prefix == "" {
		return value
	}
	if value == "" {
		return prefix
	}
	return prefix + ":" + value
}

// RuleSource returns the formatted source identifier (e.g. "sg:sg-12345" or "cidr:10.0.0.0/8").
func (r SGRule) RuleSource() string {
	return formatPrefixed(r.SourceType, r.SourceValue)
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

// Allows reports whether the security group rule permits access from src to dst,
// either via internal access (SG reference or broad CIDR within same VPC) or via
// cross-VPC broad CIDR routing when crossVPC is true.
// Returns true and the path type ("sg-ref", "cidr", or "cross-vpc").
// Safe on nil src and dst.
func (r SGRule) Allows(src, dst *Host, crossVPC bool) (bool, string) {
	if src == nil || dst == nil {
		return false, ""
	}
	if ok, pathType := r.IsInternal(src, dst); ok {
		return true, pathType
	}
	if crossVPC && r.HasBroadInternalCIDR() {
		return true, "cross-vpc"
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

// SafeID returns the subnet's ID, or an empty string if receiver is nil.
func (s *Subnet) SafeID() string {
	if s == nil {
		return ""
	}
	return s.ID
}

// Tag returns the tag value for key, or an empty string if untagged or receiver is nil.
func (s *Subnet) Tag(key string) string {
	if s == nil {
		return ""
	}
	return s.Tags[key]
}

// IsPrivate returns true if the subnet is tagged stave:subnet-type=private.
// Safe on nil receiver.
func (s *Subnet) IsPrivate() bool { return s.Tag("stave:subnet-type") == "private" }

// HasRouteTable reports whether the subnet is associated with a route table.
// Safe on nil receiver.
func (s *Subnet) HasRouteTable() bool {
	return s != nil && s.RouteTableID != ""
}

// HasInternetEgress reports whether the subnet has a default route to an internet sink
// (igw, nat, or eigw) within the given graph. Safe on nil receiver or nil graph.
func (s *Subnet) HasInternetEgress(g *Graph) bool {
	if s == nil || g == nil {
		return false
	}
	route, ok := g.DefaultRouteForSubnet(s)
	if !ok {
		return false
	}
	return route.ClassifyTarget().IsSink()
}

// HasDefaultRoute reports whether the subnet is associated with a route table
// that defines a default route (0.0.0.0/0 or ::/0) within the given graph.
// Safe on nil receiver or nil graph.
func (s *Subnet) HasDefaultRoute(g *Graph) bool {
	if s == nil || g == nil {
		return false
	}
	_, ok := g.DefaultRouteForSubnet(s)
	return ok
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
	return formatPrefixed(r.TargetType, r.TargetID)
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

// NewGraph allocates an initialized Graph with empty collections.
func NewGraph() *Graph {
	return &Graph{
		Hosts:     make(map[string]*Host),
		SGRules:   make(map[string][]SGRule),
		Subnets:   make(map[string]*Subnet),
		Routes:    make(map[string][]Route),
		Firewalls: make(map[string]bool),
	}
}

// BuildGraph extracts network topology from observation snapshots.
func BuildGraph(snapshots []asset.Snapshot) *Graph {
	g := NewGraph()
	if GraphTypes.Instance == "" {
		return g
	}
	for i := range snapshots {
		for j := range snapshots[i].Assets {
			g.extractAsset(&snapshots[i].Assets[j]) //nolint:gosec // index is within range
		}
	}
	return g
}

// extractAsset routes an asset to its specialized topology extractor.
// Safe on nil receiver or nil asset.
func (g *Graph) extractAsset(a *asset.Asset) {
	if g == nil || a == nil || a.Type == "" {
		return
	}
	switch string(a.Type) {
	case GraphTypes.Instance:
		g.extractHost(a)
	case GraphTypes.SecurityGroup:
		g.extractSGRules(a)
	case GraphTypes.PeeringConnection:
		g.extractPeering(a)
	case GraphTypes.Subnet:
		g.extractSubnet(a)
	case GraphTypes.RouteTable:
		g.extractRouteTable(a)
	case GraphTypes.Firewall:
		g.extractFirewall(a)
	case GraphTypes.TransitGateway:
		g.extractTGWAttachment(a)
	}
}

func extractTags(props map[string]any) map[string]string {
	tags := make(map[string]string)
	if rawTags, ok := props["tags"].(map[string]any); ok {
		for k, v := range rawTags {
			if s, ok := v.(string); ok {
				tags[k] = strings.ToLower(s)
			}
		}
	}
	return tags
}

func extractStringSlice(props map[string]any, key string) []string {
	if props == nil {
		return nil
	}
	raw, ok := props[key].([]any)
	if !ok {
		return nil
	}
	var items []string
	for _, item := range raw {
		if s, ok := item.(string); ok {
			items = append(items, s)
		}
	}
	return items
}

func stringProp(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	s, _ := props[key].(string)
	return s
}

func parseHost(a *asset.Asset) *Host {
	if a == nil {
		return nil
	}
	h := &Host{
		ID:   string(a.ID),
		Tags: extractTags(a.Properties),
	}
	if compute, ok := nested(a.Properties, "compute", "instance"); ok {
		h.VPCID = stringProp(compute, "vpc_id")
		h.SubnetID = stringProp(compute, "subnet_id")
		h.PrivateIP = stringProp(compute, "private_ip")
		h.PublicIP = stringProp(compute, "public_ip")
		h.SGIDs = extractStringSlice(compute, "security_groups")
	}
	return h
}

func (g *Graph) extractHost(a *asset.Asset) {
	if h := parseHost(a); h != nil {
		g.Hosts[h.ID] = h
	}
}

func parseSGRule(rm map[string]any) SGRule {
	rule := SGRule{
		Protocol: "tcp",
	}
	rule.Direction = stringProp(rm, "direction")
	rule.Protocol = stringProp(rm, "protocol")
	rule.SourceType = stringProp(rm, "source_type")
	rule.SourceValue = stringProp(rm, "source_value")
	if p, ok := rm["from_port"].(float64); ok {
		rule.Port = int(p)
	}
	return rule
}

func parseSGRules(a *asset.Asset) (string, []SGRule) {
	if a == nil {
		return "", nil
	}
	sgID := string(a.ID)
	sg, ok := nested(a.Properties, "network", "security_group")
	if !ok {
		return sgID, nil
	}
	rawRules, ok := sg["rules"].([]any)
	if !ok {
		return sgID, nil
	}
	var rules []SGRule
	for _, r := range rawRules {
		if rm, ok := r.(map[string]any); ok {
			rules = append(rules, parseSGRule(rm))
		}
	}
	return sgID, rules
}

func (g *Graph) extractSGRules(a *asset.Asset) {
	if sgID, rules := parseSGRules(a); sgID != "" && len(rules) > 0 {
		g.SGRules[sgID] = append(g.SGRules[sgID], rules...)
	}
}

func parsePeering(a *asset.Asset) VPCPeering {
	if a == nil {
		return VPCPeering{}
	}
	p := VPCPeering{PeeringID: string(a.ID)}
	if net, ok := nested(a.Properties, "network", "peering"); ok {
		p.RequesterVPC = stringProp(net, "requester_vpc")
		p.AccepterVPC = stringProp(net, "accepter_vpc")
	}
	return p
}

func (g *Graph) extractPeering(a *asset.Asset) {
	g.Peerings = append(g.Peerings, parsePeering(a))
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

// allHosts returns all hosts in the graph as a slice. Safe on nil receiver.
func (g *Graph) allHosts() []*Host {
	if g == nil {
		return nil
	}
	out := make([]*Host, 0, len(g.Hosts))
	for _, h := range g.Hosts {
		out = append(out, h)
	}
	return out
}

func (g *Graph) filterHosts(predicate func(*Host) bool) []*Host {
	if g == nil {
		return nil
	}
	var out []*Host
	for _, h := range g.Hosts {
		if predicate(h) {
			out = append(out, h)
		}
	}
	return out
}

// ProductionHosts returns all hosts tagged stave:environment=production.
// Safe on nil receiver.
func (g *Graph) ProductionHosts() []*Host {
	return g.filterHosts((*Host).IsProduction)
}

// BastionHosts returns all hosts tagged stave:role=bastion.
// Safe on nil receiver.
func (g *Graph) BastionHosts() []*Host {
	return g.filterHosts((*Host).IsBastion)
}

// DevelopmentHosts returns all hosts tagged stave:environment=development.
// Safe on nil receiver.
func (g *Graph) DevelopmentHosts() []*Host {
	return g.filterHosts((*Host).IsDevelopment)
}

// DatabaseHosts returns all hosts tagged stave:tier=database.
// Safe on nil receiver.
func (g *Graph) DatabaseHosts() []*Host {
	return g.filterHosts((*Host).IsDatabaseTier)
}

// IsolatedHosts returns all hosts tagged stave:network-zone=isolated.
// Safe on nil receiver.
func (g *Graph) IsolatedHosts() []*Host {
	return g.filterHosts((*Host).IsIsolated)
}

// PrivateSubnets returns all subnets tagged stave:subnet-type=private.
// Safe on nil receiver.
func (g *Graph) PrivateSubnets() []*Subnet {
	if g == nil {
		return nil
	}
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

// DefaultRouteForSubnet returns the first default route (0.0.0.0/0 or ::/0)
// associated with the subnet's route table, or false if none exists.
// Safe on nil receiver or nil subnet.
func (g *Graph) DefaultRouteForSubnet(sub *Subnet) (Route, bool) {
	if g == nil || !sub.HasRouteTable() {
		return Route{}, false
	}
	for _, route := range g.RoutesForSubnet(sub) {
		if route.IsDefaultRoute() {
			return route, true
		}
	}
	return Route{}, false
}

// SubnetHasInternetEgress reports whether sub has a default route to an internet sink.
// Safe on nil receiver or nil subnet.
func (g *Graph) SubnetHasInternetEgress(sub *Subnet) bool {
	return sub.HasInternetEgress(g)
}

// SubnetHasDefaultRoute reports whether sub has a default route in its route table.
// Safe on nil receiver or nil subnet.
func (g *Graph) SubnetHasDefaultRoute(sub *Subnet) bool {
	return sub.HasDefaultRoute(g)
}

func parseSubnet(a *asset.Asset) *Subnet {
	if a == nil {
		return nil
	}
	s := &Subnet{
		ID:   string(a.ID),
		Tags: extractTags(a.Properties),
	}
	if net, ok := nested(a.Properties, "network", "subnet"); ok {
		s.VPCID = stringProp(net, "vpc_id")
		s.RouteTableID = stringProp(net, "route_table_id")
	}
	return s
}

func (g *Graph) extractSubnet(a *asset.Asset) {
	if s := parseSubnet(a); s != nil {
		g.Subnets[s.ID] = s
	}
}

func parseRoute(rm map[string]any) Route {
	route := Route{}
	route.Destination = stringProp(rm, "destination")
	route.TargetType = strings.ToLower(stringProp(rm, "target_type"))
	route.TargetID = stringProp(rm, "target_id")
	return route
}

func parseRouteTableRoutes(a *asset.Asset) (string, []Route) {
	if a == nil {
		return "", nil
	}
	rtID := string(a.ID)
	rt, ok := nested(a.Properties, "network", "route_table")
	if !ok {
		return rtID, nil
	}
	rawRoutes, ok := rt["routes"].([]any)
	if !ok {
		return rtID, nil
	}
	var routes []Route
	for _, r := range rawRoutes {
		if rm, ok := r.(map[string]any); ok {
			routes = append(routes, parseRoute(rm))
		}
	}
	return rtID, routes
}

func (g *Graph) extractRouteTable(a *asset.Asset) {
	if rtID, routes := parseRouteTableRoutes(a); rtID != "" && len(routes) > 0 {
		g.Routes[rtID] = append(g.Routes[rtID], routes...)
	}
}

func parseFirewallEndpoints(a *asset.Asset) []string {
	if a == nil {
		return nil
	}
	fw, ok := nested(a.Properties, "network", "firewall")
	if !ok {
		return nil
	}
	return extractStringSlice(fw, "endpoints")
}

func (g *Graph) extractFirewall(a *asset.Asset) {
	for _, epID := range parseFirewallEndpoints(a) {
		g.Firewalls[epID] = true
	}
}

func parseTGWAttachment(a *asset.Asset) (TGWAttachment, bool) {
	if a == nil {
		return TGWAttachment{}, false
	}
	tgw, ok := nested(a.Properties, "network", "transit_gateway")
	if !ok {
		return TGWAttachment{}, false
	}
	att := TGWAttachment{
		AttachmentID:     string(a.ID),
		TransitGatewayID: stringProp(tgw, "transit_gateway_id"),
		VPCID:            stringProp(tgw, "vpc_id"),
	}
	return att, true
}

func (g *Graph) extractTGWAttachment(a *asset.Asset) {
	if att, ok := parseTGWAttachment(a); ok {
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

func (g *Graph) tgwVPCMap() map[string][]string {
	if g == nil {
		return nil
	}
	tgws := make(map[string][]string)
	for _, att := range g.TGWAttachments {
		tgws[att.TransitGatewayID] = append(tgws[att.TransitGatewayID], att.VPCID)
	}
	return tgws
}

func (g *Graph) vpcsConnectedViaTGW(vpc1, vpc2 string) bool {
	if g == nil || vpc1 == "" || vpc2 == "" {
		return false
	}
	for _, vpcs := range g.tgwVPCMap() {
		if slices.Contains(vpcs, vpc1) && slices.Contains(vpcs, vpc2) {
			return true
		}
	}
	return false
}
