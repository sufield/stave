package derive

import (
	"net/netip"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestPrefixContains(t *testing.T) {
	tests := []struct {
		super, sub string
		want       bool
	}{
		{"10.0.0.0/16", "10.0.1.0/24", true},
		{"10.0.0.0/16", "10.1.0.0/24", false},
		{"10.0.0.0/8", "10.0.1.0/24", true},
		{"10.0.0.0/8", "10.1.2.0/24", true},
		{"10.0.0.0/8", "172.16.0.0/24", false},
		{"10.0.1.0/24", "10.0.0.0/16", false}, // subnet can't contain supernet
		{"10.0.0.0/16", "10.0.0.0/16", true},  // equal
	}
	for _, tt := range tests {
		super := netip.MustParsePrefix(tt.super)
		sub := netip.MustParsePrefix(tt.sub)
		if got := prefixContains(super, sub); got != tt.want {
			t.Errorf("prefixContains(%s, %s) = %v, want %v", tt.super, tt.sub, got, tt.want)
		}
	}
}

func TestEnrichSGCoverage_AllCovered(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSubnet("subnet-1", "vpc-1", "10.0.1.0/24"),
			makeSubnet("subnet-2", "vpc-1", "10.0.2.0/24"),
			makeSG("sg-1", "vpc-1", []map[string]any{
				{"cidr_blocks": []any{"10.0.0.0/16"}, "from_port": float64(443), "to_port": float64(443)},
			}),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	sg := findAsset(out[0], "sg-1")
	cov := sgCoverage(t, sg)

	if !cov["covers_all_vpc_subnets"].(bool) {
		t.Error("expected covers_all_vpc_subnets=true; /16 covers both /24s")
	}
	if cov["uncovered_subnet_count"].(float64) != 0 {
		t.Errorf("expected 0 uncovered, got %v", cov["uncovered_subnet_count"])
	}
}

func TestEnrichSGCoverage_PartialCoverage(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSubnet("subnet-1", "vpc-1", "10.0.1.0/24"),
			makeSubnet("subnet-2", "vpc-1", "10.0.2.0/24"),
			makeSubnet("subnet-3", "vpc-1", "10.1.1.0/24"),
			makeSubnet("subnet-4", "vpc-1", "10.1.2.0/24"),
			makeSG("sg-1", "vpc-1", []map[string]any{
				{"cidr_blocks": []any{"10.0.1.0/24", "10.0.2.0/24"}, "from_port": float64(8080), "to_port": float64(8080)},
			}),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	sg := findAsset(out[0], "sg-1")
	cov := sgCoverage(t, sg)

	if cov["covers_all_vpc_subnets"].(bool) {
		t.Error("expected covers_all_vpc_subnets=false; two subnets in 10.1.x.x not covered")
	}
	if cov["uncovered_subnet_count"].(float64) != 2 {
		t.Errorf("expected 2 uncovered, got %v", cov["uncovered_subnet_count"])
	}
}

func TestEnrichSGCoverage_SkipsBroadAccess(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSubnet("subnet-1", "vpc-1", "10.0.1.0/24"),
			makeSG("sg-1", "vpc-1", []map[string]any{
				{"cidr_blocks": []any{"0.0.0.0/0"}, "from_port": float64(443), "to_port": float64(443)},
			}),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	sg := findAsset(out[0], "sg-1")
	net := sg.Properties["network"].(map[string]any)
	sgProps := net["security_group"].(map[string]any)
	if _, exists := sgProps["cidr_coverage"]; exists {
		t.Error("expected no cidr_coverage when only 0.0.0.0/0 rules exist")
	}
}

func TestEnrichNACLCoverage_PartialCoverage(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSubnet("subnet-1", "vpc-1", "10.0.1.0/24"),
			makeSubnet("subnet-2", "vpc-1", "10.0.2.0/24"),
			makeSubnet("subnet-3", "vpc-1", "10.1.1.0/24"),
			makeNACL("acl-1", "vpc-1",
				[]any{"subnet-1", "subnet-2", "subnet-3"},
				[]any{
					map[string]any{"rule_number": float64(100), "action": "allow", "cidr_block": "10.0.1.0/24"},
					map[string]any{"rule_number": float64(200), "action": "allow", "cidr_block": "10.0.2.0/24"},
					map[string]any{"rule_number": float64(32767), "action": "deny", "cidr_block": "0.0.0.0/0"},
				},
			),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	nacl := findAsset(out[0], "acl-1")
	cov := naclCoverage(t, nacl)

	if cov["covers_all_associated_subnets"].(bool) {
		t.Error("expected covers_all_associated_subnets=false; subnet-3 (10.1.1.0/24) not covered")
	}
	if cov["uncovered_subnet_count"].(float64) != 1 {
		t.Errorf("expected 1 uncovered, got %v", cov["uncovered_subnet_count"])
	}
}

func TestEnrichNACLCoverage_AllCovered(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSubnet("subnet-1", "vpc-1", "10.0.1.0/24"),
			makeSubnet("subnet-2", "vpc-1", "10.0.2.0/24"),
			makeNACL("acl-1", "vpc-1",
				[]any{"subnet-1", "subnet-2"},
				[]any{
					map[string]any{"rule_number": float64(100), "action": "allow", "cidr_block": "10.0.0.0/16"},
					map[string]any{"rule_number": float64(32767), "action": "deny", "cidr_block": "0.0.0.0/0"},
				},
			),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	nacl := findAsset(out[0], "acl-1")
	cov := naclCoverage(t, nacl)

	if !cov["covers_all_associated_subnets"].(bool) {
		t.Error("expected covers_all_associated_subnets=true; /16 covers both /24s")
	}
}

func TestEnrichNoSubnets(t *testing.T) {
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSG("sg-1", "vpc-1", []map[string]any{
				{"cidr_blocks": []any{"10.0.1.0/24"}, "from_port": float64(443), "to_port": float64(443)},
			}),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	sg := findAsset(out[0], "sg-1")
	net := sg.Properties["network"].(map[string]any)
	sgProps := net["security_group"].(map[string]any)
	if _, exists := sgProps["cidr_coverage"]; exists {
		t.Error("expected no cidr_coverage when no subnets exist in snapshot")
	}
}

func TestIsInternalCIDR(t *testing.T) {
	tests := []struct {
		cidr string
		want bool
	}{
		{"10.0.1.0/24", true},
		{"172.16.5.0/24", true},
		{"192.168.1.0/24", true},
		{"8.8.8.0/24", false},
		{"100.64.0.0/16", false},
	}
	for _, tt := range tests {
		pfx := netip.MustParsePrefix(tt.cidr)
		if got := isInternalCIDR(pfx); got != tt.want {
			t.Errorf("isInternalCIDR(%s) = %v, want %v", tt.cidr, got, tt.want)
		}
	}
}

// --- helpers ---

func makeSubnet(id, vpcID, cidr string) asset.Asset {
	return asset.Asset{
		ID:   asset.ID(id),
		Type: "aws_subnet",
		Properties: map[string]any{
			"network": map[string]any{
				"kind":       "subnet",
				"subnet_id":  id,
				"vpc_id":     vpcID,
				"cidr_block": cidr,
			},
		},
	}
}

func makeSG(id, vpcID string, rules []map[string]any) asset.Asset {
	anyRules := make([]any, len(rules))
	for i, r := range rules {
		anyRules[i] = r
	}
	return asset.Asset{
		ID:   asset.ID(id),
		Type: "aws_ec2_security_group",
		Properties: map[string]any{
			"network": map[string]any{
				"kind":   "security_group",
				"vpc_id": vpcID,
				"security_group": map[string]any{
					"ingress_rules": anyRules,
				},
			},
		},
	}
}

func makeNACL(id, vpcID string, associatedSubnetIDs []any, inboundRules []any) asset.Asset {
	return asset.Asset{
		ID:   asset.ID(id),
		Type: "aws_vpc_network_acl",
		Properties: map[string]any{
			"network": map[string]any{
				"kind":   "network_acl",
				"vpc_id": vpcID,
				"nacl": map[string]any{
					"is_custom":             true,
					"associated_subnet_ids": associatedSubnetIDs,
					"inbound_rules":         inboundRules,
				},
			},
		},
	}
}

func findAsset(snap asset.Snapshot, id string) asset.Asset {
	for _, a := range snap.Assets {
		if string(a.ID) == id {
			return a
		}
	}
	panic("asset not found: " + id)
}

func sgCoverage(t *testing.T, a asset.Asset) map[string]any {
	t.Helper()
	net := a.Properties["network"].(map[string]any)
	sg := net["security_group"].(map[string]any)
	cov, ok := sg["cidr_coverage"].(map[string]any)
	if !ok {
		t.Fatal("cidr_coverage not set on SG")
	}
	return cov
}

func naclCoverage(t *testing.T, a asset.Asset) map[string]any {
	t.Helper()
	net := a.Properties["network"].(map[string]any)
	nacl := net["nacl"].(map[string]any)
	cov, ok := nacl["cidr_coverage"].(map[string]any)
	if !ok {
		t.Fatal("cidr_coverage not set on NACL")
	}
	return cov
}

func TestBugHunt_IsInternalCIDR_SupernetsNotInternal(t *testing.T) {
	// A CIDR block like 10.0.0.0/7 starts inside 10.0.0.0/8, but extends into public IP space (up to 11.255.255.255).
	// Under correct behavior: it is not fully internal, so isInternalCIDR should return false,
	// meaning it won't be considered for internal subnet CIDR coverage comparison.
	// Under the buggy code: since 10.0.0.0 is inside 10.0.0.0/8, it evaluates to true,
	// and incorrectly treats the SG rule (allowing 10.0.0.0/7) as internal-only coverage.
	
	snap := asset.Snapshot{
		Assets: []asset.Asset{
			makeSubnet("subnet-1", "vpc-1", "10.0.1.0/24"),
			makeSG("sg-1", "vpc-1", []map[string]any{
				{"cidr_blocks": []any{"10.0.0.0/7"}, "from_port": float64(443), "to_port": float64(443)},
			}),
		},
	}

	out := EnrichVPCCIDRCoverage([]asset.Snapshot{snap})
	sg := findAsset(out[0], "sg-1")
	net := sg.Properties["network"].(map[string]any)
	sgProps := net["security_group"].(map[string]any)
	if _, exists := sgProps["cidr_coverage"]; exists {
		t.Error("expected no cidr_coverage when rule CIDR is a supernet that spans outside RFC 1918 (partially public)")
	}
}
