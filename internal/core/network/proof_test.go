package network

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
)

func TestProveBastionSSH_Enforced(t *testing.T) {
	snapshots := []asset.Snapshot{bastionEnforcedSnapshot()}
	g := BuildGraph(snapshots)

	result := g.ProveBastionSSH(22)
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (bastion routing holds), got %s", result.Result)
	}
	if result.Counterexample != nil {
		t.Fatalf("expected no counterexample, got %+v", result.Counterexample)
	}
	if result.ProductionHosts != 2 {
		t.Errorf("expected 2 production hosts, got %d", result.ProductionHosts)
	}
	if result.BastionHosts != 1 {
		t.Errorf("expected 1 bastion host, got %d", result.BastionHosts)
	}
}

func TestProveBastionSSH_Bypassed(t *testing.T) {
	snapshots := []asset.Snapshot{bastionBypassedSnapshot()}
	g := BuildGraph(snapshots)

	result := g.ProveBastionSSH(22)
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (bypass exists), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	ce := result.Counterexample
	if ce.Destination != "i-prod-app-01" && ce.Destination != "i-prod-app-02" {
		t.Errorf("expected bypass to a production host, got destination %s", ce.Destination)
	}
	if ce.Source != "i-dev-01" {
		t.Errorf("expected bypass from dev host, got source %s", ce.Source)
	}
}

func TestProveBastionSSH_PeeringBypass(t *testing.T) {
	snapshots := []asset.Snapshot{peeringBypassSnapshot()}
	g := BuildGraph(snapshots)

	result := g.ProveBastionSSH(22)
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (cross-VPC bypass exists), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.PathType != "cross-vpc" {
		t.Errorf("expected cross-vpc path type, got %s", result.Counterexample.PathType)
	}
}

func TestEnumerateSSHPaths(t *testing.T) {
	snapshots := []asset.Snapshot{bastionBypassedSnapshot()}
	g := BuildGraph(snapshots)

	paths := g.EnumerateSSHPaths(22)
	if len(paths) == 0 {
		t.Fatal("expected at least one SSH path")
	}
	hasCIDR := false
	for _, p := range paths {
		if p.PathType == "cidr" {
			hasCIDR = true
		}
	}
	if !hasCIDR {
		t.Error("expected at least one CIDR-based path (the bypass)")
	}
}

// --- test fixtures ---

func bastionEnforcedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "bastion"}),
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			hostAsset("i-prod-app-02", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
			}),
		},
	}
}

func bastionBypassedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "bastion"}),
			hostAsset("i-dev-01", "vpc-prod", "subnet-d", []string{"sg-dev"}, nil),
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			hostAsset("i-prod-app-02", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-dev", nil),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			}),
		},
	}
}

func peeringBypassSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "bastion"}),
			hostAsset("i-dev-01", "vpc-dev", "subnet-d", []string{"sg-dev"}, nil),
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-dev", nil),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			}),
			peeringAsset("pcx-01", "vpc-dev", "vpc-prod"),
		},
	}
}

func hostAsset(id, vpcID, subnetID string, sgs []string, tags map[string]string) asset.Asset {
	sgAny := make([]any, len(sgs))
	for i, s := range sgs {
		sgAny[i] = s
	}
	tagMap := make(map[string]any, len(tags))
	for k, v := range tags {
		tagMap[k] = v
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_ec2_instance",
		Vendor: "aws",
		Properties: map[string]any{
			"compute": map[string]any{
				"instance": map[string]any{
					"vpc_id":          vpcID,
					"subnet_id":       subnetID,
					"security_groups": sgAny,
					"private_ip":      "10.0.0.1",
				},
			},
			"tags": tagMap,
		},
	}
}

func sgAsset(id string, rules []SGRule) asset.Asset {
	rulesAny := make([]any, len(rules))
	for i, r := range rules {
		rulesAny[i] = map[string]any{
			"direction":    r.Direction,
			"protocol":     r.Protocol,
			"from_port":    float64(r.Port),
			"source_type":  r.SourceType,
			"source_value": r.SourceValue,
		}
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_ec2_security_group",
		Vendor: "aws",
		Properties: map[string]any{
			"network": map[string]any{
				"security_group": map[string]any{
					"rules": rulesAny,
				},
			},
		},
	}
}

func peeringAsset(id, requester, accepter string) asset.Asset {
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_vpc_peering_connection",
		Vendor: "aws",
		Properties: map[string]any{
			"network": map[string]any{
				"peering": map[string]any{
					"requester_vpc": requester,
					"accepter_vpc":  accepter,
				},
			},
		},
	}
}
