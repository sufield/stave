package derive

import (
	"net/netip"

	"github.com/sufield/stave/internal/core/asset"
)

func subnetType() string        { return VPCCIDRTypes.Subnet }
func securityGroupType() string { return VPCCIDRTypes.SecurityGroup }
func networkACLType() string    { return VPCCIDRTypes.NetworkACL }

// EnrichVPCCIDRCoverage checks whether security group ingress rules and
// NACL allow rules cover all subnet CIDRs in their VPC. It sets derived
// booleans that standard control predicates can evaluate. The asset types
// it matches are configured via VPCCIDRTypes (set by the provider at startup).
//
// Derived fields on security group assets:
//   - network.security_group.cidr_coverage.covers_all_vpc_subnets (bool)
//   - network.security_group.cidr_coverage.uncovered_subnet_count (float64)
//   - network.security_group.cidr_coverage.has_cidr_rules (bool)
//
// Derived fields on network ACL assets:
//   - network.nacl.cidr_coverage.covers_all_associated_subnets (bool)
//   - network.nacl.cidr_coverage.uncovered_subnet_count (float64)
//   - network.nacl.cidr_coverage.has_cidr_rules (bool)
func EnrichVPCCIDRCoverage(snapshots []asset.Snapshot) []asset.Snapshot {
	out := make([]asset.Snapshot, len(snapshots))
	for i, snap := range snapshots {
		out[i] = enrichSnapshotCIDRCoverage(snap)
	}
	return out
}

func enrichSnapshotCIDRCoverage(snap asset.Snapshot) asset.Snapshot {
	subnetsByVPC := collectSubnetCIDRsByVPC(snap)
	if len(subnetsByVPC) == 0 {
		return snap
	}
	subnetCIDRByID := collectSubnetCIDRByID(snap)

	enriched := snap
	enriched.Assets = make([]asset.Asset, len(snap.Assets))
	copy(enriched.Assets, snap.Assets)

	for i := range enriched.Assets {
		a := &enriched.Assets[i]
		switch {
		case a.IsType(securityGroupType()):
			enriched.Assets[i] = enrichSGCoverage(*a, subnetsByVPC)
		case a.IsType(networkACLType()):
			enriched.Assets[i] = enrichNACLCoverage(*a, subnetsByVPC, subnetCIDRByID)
		}
	}
	return enriched
}

// collectSubnetCIDRsByVPC returns vpc_id → list of parsed subnet prefixes.
func collectSubnetCIDRsByVPC(snap asset.Snapshot) map[string][]netip.Prefix {
	m := map[string][]netip.Prefix{}
	for _, a := range snap.Assets {
		if !a.IsType(subnetType()) {
			continue
		}
		net, _ := a.Properties["network"].(map[string]any)
		if net == nil {
			continue
		}
		vpcID, _ := net["vpc_id"].(string)
		cidrStr, _ := net["cidr_block"].(string)
		if vpcID == "" || cidrStr == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			continue
		}
		m[vpcID] = append(m[vpcID], pfx)
	}
	return m
}

// collectSubnetCIDRByID returns subnet_id → parsed prefix.
func collectSubnetCIDRByID(snap asset.Snapshot) map[string]netip.Prefix {
	m := map[string]netip.Prefix{}
	for _, a := range snap.Assets {
		if !a.IsType(subnetType()) {
			continue
		}
		net, _ := a.Properties["network"].(map[string]any)
		if net == nil {
			continue
		}
		subnetID, _ := net["subnet_id"].(string)
		cidrStr, _ := net["cidr_block"].(string)
		if subnetID == "" || cidrStr == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			continue
		}
		m[subnetID] = pfx
	}
	return m
}

func enrichSGCoverage(a asset.Asset, subnetsByVPC map[string][]netip.Prefix) asset.Asset {
	net, _ := a.Properties["network"].(map[string]any)
	if net == nil {
		return a
	}
	vpcID, _ := net["vpc_id"].(string)
	if vpcID == "" {
		return a
	}
	vpcSubnets, ok := subnetsByVPC[vpcID]
	if !ok || len(vpcSubnets) == 0 {
		return a
	}

	sg, _ := net["security_group"].(map[string]any)
	if sg == nil {
		return a
	}
	rules, _ := sg["ingress_rules"].([]any)
	if len(rules) == 0 {
		return a
	}

	internalCIDRs := collectInternalCIDRsFromSGRules(rules)
	if len(internalCIDRs) == 0 {
		return a
	}

	uncovered := 0
	for _, subnet := range vpcSubnets {
		if !anyCIDRContains(internalCIDRs, subnet) {
			uncovered++
		}
	}

	newProps := cloneStringAnyMap(a.Properties)
	newNet, _ := newProps["network"].(map[string]any)
	if newNet == nil {
		return a
	}
	newSG, _ := newNet["security_group"].(map[string]any)
	if newSG == nil {
		return a
	}

	coverage := map[string]any{
		"covers_all_vpc_subnets": uncovered == 0,
		"uncovered_subnet_count": float64(uncovered),
		"has_cidr_rules":         true,
	}
	newSG["cidr_coverage"] = coverage

	return asset.Asset{
		ID: a.ID, Type: a.Type, Vendor: a.Vendor,
		Properties: newProps, Source: a.Source,
	}
}

func enrichNACLCoverage(a asset.Asset, subnetsByVPC map[string][]netip.Prefix, subnetCIDRByID map[string]netip.Prefix) asset.Asset {
	net, _ := a.Properties["network"].(map[string]any)
	if net == nil {
		return a
	}
	vpcID, _ := net["vpc_id"].(string)
	nacl, _ := net["nacl"].(map[string]any)
	if nacl == nil {
		return a
	}

	associatedIDs := toStringSlice(nacl["associated_subnet_ids"])
	if len(associatedIDs) == 0 {
		return a
	}

	// Resolve associated subnet CIDRs
	var associatedSubnets []netip.Prefix
	for _, sid := range associatedIDs {
		if pfx, ok := subnetCIDRByID[sid]; ok {
			associatedSubnets = append(associatedSubnets, pfx)
		}
	}
	if len(associatedSubnets) == 0 {
		// Fall back to all VPC subnets if we can't resolve by ID
		if vpcID != "" {
			associatedSubnets = subnetsByVPC[vpcID]
		}
		if len(associatedSubnets) == 0 {
			return a
		}
	}

	inboundRules, _ := nacl["inbound_rules"].([]any)
	allowCIDRs := collectInternalCIDRsFromNACLRules(inboundRules)
	if len(allowCIDRs) == 0 {
		return a
	}

	uncovered := 0
	for _, subnet := range associatedSubnets {
		if !anyCIDRContains(allowCIDRs, subnet) {
			uncovered++
		}
	}

	newProps := cloneStringAnyMap(a.Properties)
	newNet, _ := newProps["network"].(map[string]any)
	if newNet == nil {
		return a
	}
	newNACL, _ := newNet["nacl"].(map[string]any)
	if newNACL == nil {
		return a
	}

	coverage := map[string]any{
		"covers_all_associated_subnets": uncovered == 0,
		"uncovered_subnet_count":        float64(uncovered),
		"has_cidr_rules":                true,
	}
	newNACL["cidr_coverage"] = coverage

	return asset.Asset{
		ID: a.ID, Type: a.Type, Vendor: a.Vendor,
		Properties: newProps, Source: a.Source,
	}
}

// collectInternalCIDRsFromSGRules extracts RFC 1918 / internal CIDRs from
// SG ingress rules. Skips 0.0.0.0/0 and non-internal ranges.
func collectInternalCIDRsFromSGRules(rules []any) []netip.Prefix {
	var cidrs []netip.Prefix
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		cidrBlocks, _ := rule["cidr_blocks"].([]any)
		for _, cb := range cidrBlocks {
			s, _ := cb.(string)
			if s == "" || s == "0.0.0.0/0" || s == "::/0" {
				continue
			}
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				continue
			}
			if isInternalCIDR(pfx) {
				cidrs = append(cidrs, pfx)
			}
		}
	}
	return cidrs
}

// collectInternalCIDRsFromNACLRules extracts internal CIDRs from NACL
// allow rules only (skips deny rules and 0.0.0.0/0).
func collectInternalCIDRsFromNACLRules(rules []any) []netip.Prefix {
	var cidrs []netip.Prefix
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		action, _ := rule["action"].(string)
		if action != "allow" {
			continue
		}
		cidr, _ := rule["cidr_block"].(string)
		if cidr == "" || cidr == "0.0.0.0/0" || cidr == "::/0" {
			continue
		}
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if isInternalCIDR(pfx) {
			cidrs = append(cidrs, pfx)
		}
	}
	return cidrs
}

// anyCIDRContains reports whether any CIDR in the list fully contains
// the target prefix.
func anyCIDRContains(cidrs []netip.Prefix, target netip.Prefix) bool {
	for _, c := range cidrs {
		if prefixContains(c, target) {
			return true
		}
	}
	return false
}

// prefixContains reports whether supernet fully contains subnet.
// A /16 contains a /24 within it, but not vice versa.
func prefixContains(supernet, subnet netip.Prefix) bool {
	if supernet.Bits() > subnet.Bits() {
		return false
	}
	return supernet.Contains(subnet.Addr()) &&
		supernet.Contains(lastAddr(subnet))
}

// lastAddr returns the last (broadcast) address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	raw := addr.As16()
	bits := p.Bits()
	if addr.Is4() {
		bits += 96
	}
	for i := bits; i < 128; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		raw[byteIdx] |= 1 << uint(bitIdx)
	}
	result := netip.AddrFrom16(raw)
	if addr.Is4() {
		return result.Unmap()
	}
	return result
}

var rfc1918 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

func isInternalCIDR(p netip.Prefix) bool {
	for _, r := range rfc1918 {
		if prefixContains(r, p) {
			return true
		}
	}
	return false
}

func toStringSlice(v any) []string {
	switch vv := v.(type) {
	case []string:
		return vv
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
