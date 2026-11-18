package network

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestProveBastionSSH_Enforced(t *testing.T) {
	snapshots := []asset.Snapshot{bastionEnforcedSnapshot()}
	g := BuildGraph(snapshots)

	result, err := g.ProveBastionSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

	result, err := g.ProveBastionSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

	result, err := g.ProveBastionSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

func TestProveBastionSSH_VacuousNoProduction(t *testing.T) {
	snapshots := []asset.Snapshot{noProductionSnapshot()}
	g := BuildGraph(snapshots)

	_, err := g.ProveBastionSSH(22)
	if err == nil {
		t.Fatal("expected error when no production hosts found, got nil")
	}
}

func TestProveBastionSSH_VacuousNoBastions(t *testing.T) {
	snapshots := []asset.Snapshot{noBastionSnapshot()}
	g := BuildGraph(snapshots)

	_, err := g.ProveBastionSSH(22)
	if err == nil {
		t.Fatal("expected error when no bastion hosts found, got nil")
	}
}

func TestProveBastionSSH_CaseInsensitiveEnvironment(t *testing.T) {
	snapshots := []asset.Snapshot{mixedCaseEnvSnapshot()}
	g := BuildGraph(snapshots)

	result, err := g.ProveBastionSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ProductionHosts != 1 {
		t.Errorf("expected 1 production host (case-insensitive), got %d", result.ProductionHosts)
	}
}

func TestProveBastionSSH_CaseInsensitiveBastion(t *testing.T) {
	snapshots := []asset.Snapshot{mixedCaseBastionSnapshot()}
	g := BuildGraph(snapshots)

	result, err := g.ProveBastionSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.BastionHosts != 1 {
		t.Errorf("expected 1 bastion host (case-insensitive), got %d", result.BastionHosts)
	}
}

func TestProveBastionSSH_IPv6ExternalBypass(t *testing.T) {
	snapshots := []asset.Snapshot{ipv6ExternalBypassSnapshot()}
	g := BuildGraph(snapshots)

	result, err := g.ProveBastionSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (IPv6 external bypass), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.PathType != "external" {
		t.Errorf("expected external path type, got %s", result.Counterexample.PathType)
	}
}

func TestProveBastionSSH_EmptyGraph(t *testing.T) {
	g := &Graph{
		Hosts:   make(map[string]*Host),
		SGRules: make(map[string][]SGRule),
	}
	_, err := g.ProveBastionSSH(22)
	if err == nil {
		t.Fatal("expected error on empty graph, got nil")
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

func noProductionSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "bastion"}),
			hostAsset("i-dev-01", "vpc-prod", "subnet-d", []string{"sg-dev"}, nil),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-dev", nil),
		},
	}
}

func noBastionSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			hostAsset("i-dev-01", "vpc-prod", "subnet-d", []string{"sg-dev"}, nil),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			}),
			sgAsset("sg-dev", nil),
		},
	}
}

func mixedCaseEnvSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "bastion"}),
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "Production"}),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
			}),
		},
	}
}

func mixedCaseBastionSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "BASTION"}),
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
			}),
		},
	}
}

func ipv6ExternalBypassSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-bastion-01", "vpc-prod", "subnet-b", []string{"sg-bastion"}, map[string]string{"stave:role": "bastion"}),
			hostAsset("i-prod-app-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			sgAsset("sg-bastion", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			}),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "::/0"},
			}),
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

func subnetAsset(id, vpcID, rtID string, tags map[string]string) asset.Asset {
	tagMap := make(map[string]any, len(tags))
	for k, v := range tags {
		tagMap[k] = v
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_ec2_subnet",
		Vendor: "aws",
		Properties: map[string]any{
			"network": map[string]any{
				"subnet": map[string]any{
					"vpc_id":         vpcID,
					"route_table_id": rtID,
				},
			},
			"tags": tagMap,
		},
	}
}

func routeTableAsset(id string, routes []Route) asset.Asset {
	routesAny := make([]any, len(routes))
	for i, r := range routes {
		routesAny[i] = map[string]any{
			"destination": r.Destination,
			"target_type": r.TargetType,
			"target_id":   r.TargetID,
		}
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_ec2_route_table",
		Vendor: "aws",
		Properties: map[string]any{
			"network": map[string]any{
				"route_table": map[string]any{
					"routes": routesAny,
				},
			},
		},
	}
}

func firewallAsset(id string, endpoints []string) asset.Asset {
	epAny := make([]any, len(endpoints))
	for i, ep := range endpoints {
		epAny[i] = ep
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_networkfirewall_firewall",
		Vendor: "aws",
		Properties: map[string]any{
			"network": map[string]any{
				"firewall": map[string]any{
					"endpoints": epAny,
				},
			},
		},
	}
}

// --- prod-dev-isolation tests ---

func TestProveProdDevIsolation_Isolated(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{prodDevIsolatedSnapshot()})
	result, err := g.ProveProdDevIsolation()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (environments isolated), got %s", result.Result)
	}
}

func TestProveProdDevIsolation_Connected(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{prodDevConnectedSnapshot()})
	result, err := g.ProveProdDevIsolation()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (cross-environment path exists), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.PathType != "cross-vpc" {
		t.Errorf("expected cross-vpc path type, got %s", result.Counterexample.PathType)
	}
}

func TestProveProdDevIsolation_VacuousNoDev(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{bastionEnforcedSnapshot()})
	_, err := g.ProveProdDevIsolation()
	if err == nil {
		t.Fatal("expected error when no development hosts found")
	}
}

func Test_newCrossEnvBypassCounterexample(t *testing.T) {
	src := &Host{ID: "i-dev", Tags: map[string]string{"stave:environment": "development"}}
	dst := &Host{ID: "i-prod", Tags: map[string]string{"stave:environment": "production"}}
	match := &RuleMatch{SecurityGroupID: "sg-prod", RuleSource: "10.0.0.0/8", PathType: "cross-vpc", Port: 443}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newCrossEnvBypassCounterexample(nil, dst, match); ce != nil {
			t.Errorf("expected nil for nil src, got %+v", ce)
		}
		if ce := newCrossEnvBypassCounterexample(src, nil, match); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newCrossEnvBypassCounterexample(src, dst, nil); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with source, destination, and explanation", func(t *testing.T) {
		ce := newCrossEnvBypassCounterexample(src, dst, match)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-dev" || ce.Destination != "i-prod" || ce.Port != 443 || ce.PathType != "cross-vpc" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
		if !strings.Contains(ce.Explanation, "Host i-dev (development) can reach i-prod (production) via cross-vpc.") {
			t.Errorf("unexpected explanation: %q", ce.Explanation)
		}
		if !strings.Contains(ce.Remediation, "Remove cross-environment ingress rule on sg-prod.") {
			t.Errorf("unexpected remediation: %q", ce.Remediation)
		}
	})
}

func prodDevIsolatedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-prod-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			hostAsset("i-dev-01", "vpc-dev", "subnet-d", []string{"sg-dev"}, map[string]string{"stave:environment": "development"}),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-prod"},
			}),
			sgAsset("sg-dev", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-dev"},
			}),
		},
	}
}

func prodDevConnectedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-prod-01", "vpc-prod", "subnet-p", []string{"sg-prod"}, map[string]string{"stave:environment": "production"}),
			hostAsset("i-dev-01", "vpc-dev", "subnet-d", []string{"sg-dev"}, map[string]string{"stave:environment": "development"}),
			sgAsset("sg-prod", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			}),
			sgAsset("sg-dev", nil),
			peeringAsset("pcx-prod-dev", "vpc-prod", "vpc-dev"),
		},
	}
}

// --- database-isolation tests ---

func TestProveDatabaseIsolation_Isolated(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{databaseIsolatedSnapshot()})
	result, err := g.ProveDatabaseIsolation()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (database isolated), got %s", result.Result)
	}
}

func TestProveDatabaseIsolation_Exposed(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{databaseExposedSnapshot()})
	result, err := g.ProveDatabaseIsolation()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (database reachable from outside VPC), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.PathType != "cross-vpc" {
		t.Errorf("expected cross-vpc path type, got %s", result.Counterexample.PathType)
	}
}

func TestProveDatabaseIsolation_ExternalIngress(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{databaseExternalIngressSnapshot()})
	result, err := g.ProveDatabaseIsolation()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (database has internet ingress), got %s", result.Result)
	}
	if result.Counterexample.PathType != "external" {
		t.Errorf("expected external path type, got %s", result.Counterexample.PathType)
	}
}

func TestProveDatabaseIsolation_VacuousNoDatabase(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{bastionEnforcedSnapshot()})
	_, err := g.ProveDatabaseIsolation()
	if err == nil {
		t.Fatal("expected error when no database hosts found")
	}
}

func databaseIsolatedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-app-01", "vpc-app", "subnet-app", []string{"sg-app"}, map[string]string{"stave:tier": "application"}),
			hostAsset("i-db-01", "vpc-app", "subnet-db", []string{"sg-db"}, map[string]string{"stave:tier": "database"}),
			sgAsset("sg-app", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			}),
			sgAsset("sg-db", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 3306, SourceType: "sg", SourceValue: "sg-app"},
			}),
		},
	}
}

func databaseExposedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-db-01", "vpc-app", "subnet-db", []string{"sg-db"}, map[string]string{"stave:tier": "database"}),
			hostAsset("i-mgmt-01", "vpc-mgmt", "subnet-mgmt", []string{"sg-mgmt"}, nil),
			sgAsset("sg-db", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 3306, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			}),
			sgAsset("sg-mgmt", nil),
			peeringAsset("pcx-mgmt-app", "vpc-mgmt", "vpc-app"),
		},
	}
}

func databaseExternalIngressSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			hostAsset("i-db-01", "vpc-app", "subnet-db", []string{"sg-db"}, map[string]string{"stave:tier": "database"}),
			sgAsset("sg-db", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 3306, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			}),
		},
	}
}

// --- firewall-mandatory tests ---

func TestProveFirewallMandatory_Enforced(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{firewallEnforcedSnapshot()})
	result, err := g.ProveFirewallMandatory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (firewall enforced), got %s", result.Result)
	}
}

func TestProveFirewallMandatory_Bypassed(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{firewallBypassedSnapshot()})
	result, err := g.ProveFirewallMandatory()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (firewall bypassed), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.PathType != "direct-igw" {
		t.Errorf("expected direct-igw path type, got %s", result.Counterexample.PathType)
	}
}

func TestProveFirewallMandatory_VacuousNoSubnets(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{bastionEnforcedSnapshot()})
	_, err := g.ProveFirewallMandatory()
	if err == nil {
		t.Fatal("expected error when no private subnets found")
	}
}

func TestProveFirewallMandatory_VacuousNoFirewall(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{{
		Assets: []asset.Asset{
			subnetAsset("subnet-priv-01", "vpc-app", "rt-priv-01", map[string]string{"stave:subnet-type": "private"}),
			routeTableAsset("rt-priv-01", []Route{
				{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-01"},
			}),
		},
	}})
	_, err := g.ProveFirewallMandatory()
	if err == nil {
		t.Fatal("expected error when no firewall endpoints found")
	}
}

func firewallEnforcedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			subnetAsset("subnet-priv-01", "vpc-app", "rt-priv-01", map[string]string{"stave:subnet-type": "private"}),
			routeTableAsset("rt-priv-01", []Route{
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "vpce", TargetID: "vpce-fw-01"},
			}),
			firewallAsset("fw-01", []string{"vpce-fw-01"}),
		},
	}
}

func firewallBypassedSnapshot() asset.Snapshot {
	return asset.Snapshot{
		Assets: []asset.Asset{
			subnetAsset("subnet-priv-01", "vpc-app", "rt-priv-01", map[string]string{"stave:subnet-type": "private"}),
			routeTableAsset("rt-priv-01", []Route{
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-01"},
			}),
			firewallAsset("fw-01", []string{"vpce-fw-01"}),
		},
	}
}

// --- transit gateway tests ---

func TestCanReach_TGW(t *testing.T) {
	g := &Graph{
		Hosts: map[string]*Host{
			"i-src": {ID: "i-src", VPCID: "vpc-a", SubnetID: "subnet-a", SGIDs: []string{"sg-src"}, Tags: map[string]string{}},
			"i-dst": {ID: "i-dst", VPCID: "vpc-b", SubnetID: "subnet-b", SGIDs: []string{"sg-dst"}, Tags: map[string]string{}},
		},
		SGRules: map[string][]SGRule{
			"sg-dst": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			},
		},
		TGWAttachments: []TGWAttachment{
			{AttachmentID: "tgw-att-1", TransitGatewayID: "tgw-01", VPCID: "vpc-a"},
			{AttachmentID: "tgw-att-2", TransitGatewayID: "tgw-01", VPCID: "vpc-b"},
		},
	}
	ok, pathType := g.CanReach(g.Hosts["i-src"], g.Hosts["i-dst"], 22)
	if !ok {
		t.Fatal("expected reachability via TGW")
	}
	if pathType != "cross-vpc" {
		t.Errorf("expected cross-vpc path type, got %s", pathType)
	}
}

// --- transitive-ssh tests ---

func TestProveTransitiveSSH_SAT(t *testing.T) {
	g := &Graph{
		Hosts: map[string]*Host{
			"i-bastion": {ID: "i-bastion", VPCID: "vpc-prod", SubnetID: "subnet-b", SGIDs: []string{"sg-bastion"}, Tags: map[string]string{"stave:role": "bastion", "stave:environment": "production"}},
			"i-jumpbox": {ID: "i-jumpbox", VPCID: "vpc-prod", SubnetID: "subnet-j", SGIDs: []string{"sg-jump"}, Tags: map[string]string{}},
			"i-prod-01": {ID: "i-prod-01", VPCID: "vpc-prod", SubnetID: "subnet-p", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}},
		},
		SGRules: map[string][]SGRule{
			"sg-bastion": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			},
			"sg-jump": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			},
			"sg-prod": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-jump"},
			},
		},
	}

	result, err := g.ProveTransitiveSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (transitive SSH via jumpbox), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
}

func TestProveTransitiveSSH_UNSAT(t *testing.T) {
	g := &Graph{
		Hosts: map[string]*Host{
			"i-bastion": {ID: "i-bastion", VPCID: "vpc-prod", SubnetID: "subnet-b", SGIDs: []string{"sg-bastion"}, Tags: map[string]string{"stave:role": "bastion"}},
			"i-prod-01": {ID: "i-prod-01", VPCID: "vpc-prod", SubnetID: "subnet-p", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}},
		},
		SGRules: map[string][]SGRule{
			"sg-bastion": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			},
			"sg-prod": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
			},
		},
	}

	result, err := g.ProveTransitiveSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (only bastion can reach prod), got %s", result.Result)
	}
}

func TestProveTransitiveSSH_IPv6_SAT(t *testing.T) {
	g := &Graph{
		Hosts: map[string]*Host{
			"i-bastion": {ID: "i-bastion", VPCID: "vpc-prod", SubnetID: "subnet-b", SGIDs: []string{"sg-bastion"}, Tags: map[string]string{"stave:role": "bastion", "stave:environment": "production"}},
			"i-jumpbox": {ID: "i-jumpbox", VPCID: "vpc-prod", SubnetID: "subnet-j", SGIDs: []string{"sg-jump"}, Tags: map[string]string{}},
			"i-prod-01": {ID: "i-prod-01", VPCID: "vpc-prod", SubnetID: "subnet-p", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}},
		},
		SGRules: map[string][]SGRule{
			"sg-bastion": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			},
			"sg-jump": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "::/0"},
			},
			"sg-prod": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-jump"},
			},
		},
	}

	result, err := g.ProveTransitiveSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT, got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if want := "::/0 -> i-jumpbox"; result.Counterexample.Source != want {
		t.Errorf("Source = %q, want %q", result.Counterexample.Source, want)
	}
	if want := "Remove SSH ingress from ::/0 on i-jumpbox or remove its access to production host i-prod-01."; result.Counterexample.Remediation != want {
		t.Errorf("Remediation = %q, want %q", result.Counterexample.Remediation, want)
	}
}

func TestProveTransitiveSSH_InternalHop_SAT(t *testing.T) {
	g := &Graph{
		Hosts: map[string]*Host{
			"i-bastion": {ID: "i-bastion", VPCID: "vpc-prod", SubnetID: "subnet-b", SGIDs: []string{"sg-bastion"}, Tags: map[string]string{"stave:role": "bastion", "stave:environment": "production"}},
			"i-dev":     {ID: "i-dev", VPCID: "vpc-prod", SubnetID: "subnet-d", SGIDs: []string{"sg-dev"}, Tags: map[string]string{"stave:environment": "development"}},
			"i-relay":   {ID: "i-relay", VPCID: "vpc-prod", SubnetID: "subnet-r", SGIDs: []string{"sg-relay"}, Tags: map[string]string{}},
			"i-prod-01": {ID: "i-prod-01", VPCID: "vpc-prod", SubnetID: "subnet-p", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}},
		},
		SGRules: map[string][]SGRule{
			"sg-bastion": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "203.0.113.0/24"},
			},
			"sg-dev": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			},
			"sg-relay": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-dev"},
			},
			"sg-prod": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-relay"},
			},
		},
	}

	result, err := g.ProveTransitiveSSH(22)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT, got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if want := "i-dev -> i-relay"; result.Counterexample.Source != want {
		t.Errorf("Source = %q, want %q", result.Counterexample.Source, want)
	}
	if want := "transitive"; result.Counterexample.PathType != want {
		t.Errorf("PathType = %q, want %q", result.Counterexample.PathType, want)
	}
}

func TestGraph_findTransitiveBypass_NilChecks(t *testing.T) {
	var nilGraph *Graph
	relay := &Host{ID: "i-relay"}
	dst := &Host{ID: "i-dst"}
	ruleMatch := &RuleMatch{SecurityGroupID: "sg-1", RuleSource: "sg:sg-2", PathType: "sg-ref", Port: 22}

	if ce := nilGraph.findTransitiveInternetBypass(relay, dst, 22, ruleMatch); ce != nil {
		t.Errorf("expected nil counterexample from nil graph, got %+v", ce)
	}
	if ce := nilGraph.findTransitiveInternalBypass(relay, relay, dst, 22, ruleMatch); ce != nil {
		t.Errorf("expected nil counterexample from nil graph, got %+v", ce)
	}

	g := &Graph{}
	if ce := g.findTransitiveInternetBypass(relay, dst, 22, nil); ce != nil {
		t.Errorf("expected nil counterexample for nil relayMatch, got %+v", ce)
	}
	if ce := g.findTransitiveInternalBypass(relay, relay, dst, 22, nil); ce != nil {
		t.Errorf("expected nil counterexample for nil relayMatch, got %+v", ce)
	}
}

// --- transitive-egress tests ---

func TestProveTransitiveEgress_SAT(t *testing.T) {
	// Isolated workload can reach a service host whose subnet has NAT egress.
	// Two-hop path: isolated → service → internet (via NAT).
	g := &Graph{
		Hosts: map[string]*Host{
			"i-sandbox": {ID: "i-sandbox", VPCID: "vpc-ml", SubnetID: "subnet-iso", SGIDs: []string{"sg-sandbox"}, Tags: map[string]string{"stave:network-zone": "isolated"}},
			"i-mirror":  {ID: "i-mirror", VPCID: "vpc-ml", SubnetID: "subnet-svc", SGIDs: []string{"sg-mirror"}, Tags: map[string]string{"stave:role": "package-mirror"}},
		},
		SGRules: map[string][]SGRule{
			"sg-sandbox": {},
			"sg-mirror": {
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"},
			},
		},
		Subnets: map[string]*Subnet{
			"subnet-iso": {ID: "subnet-iso", VPCID: "vpc-ml", RouteTableID: "rt-iso", Tags: map[string]string{"stave:subnet-type": "private"}},
			"subnet-svc": {ID: "subnet-svc", VPCID: "vpc-ml", RouteTableID: "rt-svc", Tags: map[string]string{"stave:subnet-type": "private"}},
		},
		Routes: map[string][]Route{
			"rt-iso": {{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}},
			"rt-svc": {
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
			},
		},
		Firewalls: map[string]bool{},
	}

	result, err := g.ProveTransitiveEgress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT (transitive egress via mirror), got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.PathType != "transitive-egress" {
		t.Errorf("expected transitive-egress path type, got %s", result.Counterexample.PathType)
	}
}

func TestProveTransitiveEgress_UNSAT(t *testing.T) {
	// Isolated workload cannot reach any host with internet egress.
	g := &Graph{
		Hosts: map[string]*Host{
			"i-sandbox": {ID: "i-sandbox", VPCID: "vpc-ml", SubnetID: "subnet-iso", SGIDs: []string{"sg-sandbox"}, Tags: map[string]string{"stave:network-zone": "isolated"}},
			"i-mirror":  {ID: "i-mirror", VPCID: "vpc-ml", SubnetID: "subnet-svc", SGIDs: []string{"sg-mirror"}, Tags: map[string]string{"stave:role": "package-mirror"}},
		},
		SGRules: map[string][]SGRule{
			"sg-sandbox": {},
			"sg-mirror": {
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-mirror"},
			},
		},
		Subnets: map[string]*Subnet{
			"subnet-iso": {ID: "subnet-iso", VPCID: "vpc-ml", RouteTableID: "rt-iso", Tags: map[string]string{"stave:subnet-type": "private"}},
			"subnet-svc": {ID: "subnet-svc", VPCID: "vpc-ml", RouteTableID: "rt-svc", Tags: map[string]string{"stave:subnet-type": "private"}},
		},
		Routes: map[string][]Route{
			"rt-iso": {{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}},
			"rt-svc": {
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
			},
		},
		Firewalls: map[string]bool{},
	}

	result, err := g.ProveTransitiveEgress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT (no reachability from sandbox to mirror), got %s", result.Result)
	}
}

func TestProveTransitiveEgress_VacuousNoIsolated(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{bastionEnforcedSnapshot()})
	_, err := g.ProveTransitiveEgress()
	if err == nil {
		t.Fatal("expected error when no isolated hosts found")
	}
}

func TestProveTransitiveEgress_BuildGraph_SAT(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{{
		Assets: []asset.Asset{
			hostAsset("i-iso", "vpc-ml", "subnet-iso", []string{"sg-iso"}, map[string]string{"stave:network-zone": "isolated"}),
			hostAsset("i-egress", "vpc-ml", "subnet-egr", []string{"sg-egr"}, map[string]string{"stave:role": "mirror"}),
			sgAsset("sg-iso", nil),
			sgAsset("sg-egr", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-iso"},
			}),
			subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
			subnetAsset("subnet-egr", "vpc-ml", "rt-egr", nil),
			routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
			routeTableAsset("rt-egr", []Route{
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
			}),
		},
	}})
	result, err := g.ProveTransitiveEgress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "SAT" {
		t.Fatalf("expected SAT, got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample")
	}
	if result.Counterexample.RuleSG == "" {
		t.Error("expected RuleSG populated")
	}
}

func TestProveTransitiveEgress_BuildGraph_UNSAT(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{{
		Assets: []asset.Asset{
			hostAsset("i-iso", "vpc-ml", "subnet-iso", []string{"sg-iso"}, map[string]string{"stave:network-zone": "isolated"}),
			hostAsset("i-egress", "vpc-ml", "subnet-egr", []string{"sg-egr"}, map[string]string{"stave:role": "mirror"}),
			sgAsset("sg-iso", nil),
			sgAsset("sg-egr", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-egr"},
			}),
			subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
			subnetAsset("subnet-egr", "vpc-ml", "rt-egr", nil),
			routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
			routeTableAsset("rt-egr", []Route{
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
			}),
		},
	}})
	result, err := g.ProveTransitiveEgress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "UNSAT" {
		t.Fatalf("expected UNSAT, got %s", result.Result)
	}
}

func TestProveTransitiveEgress_BuildGraph_EvidenceGated(t *testing.T) {
	g := BuildGraph([]asset.Snapshot{{
		Assets: []asset.Asset{
			hostAsset("i-iso", "vpc-ml", "subnet-iso", []string{"sg-iso"}, map[string]string{"stave:network-zone": "isolated"}),
			hostAsset("i-relay", "vpc-ml", "subnet-tgw", []string{"sg-relay"}, map[string]string{"stave:role": "relay"}),
			sgAsset("sg-iso", nil),
			sgAsset("sg-relay", []SGRule{
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-iso"},
			}),
			subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
			subnetAsset("subnet-tgw", "vpc-ml", "rt-tgw", nil),
			routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
			routeTableAsset("rt-tgw", []Route{
				{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
				{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-att-01"},
			}),
		},
	}})
	result, err := g.ProveTransitiveEgress()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Result != "EVIDENCE_GATED" {
		t.Fatalf("expected EVIDENCE_GATED, got %s", result.Result)
	}
	if result.Counterexample == nil {
		t.Fatal("expected counterexample with gated path info")
	}
	if result.Counterexample.PathType != "gated-egress" {
		t.Errorf("expected gated-egress path type, got %s", result.Counterexample.PathType)
	}
}

func routeTableAssetWithState(id string, routes []map[string]any) asset.Asset {
	routesAny := make([]any, len(routes))
	for i, r := range routes {
		routesAny[i] = r
	}
	return asset.Asset{
		ID:     asset.ID(id),
		Type:   "aws_ec2_route_table",
		Vendor: "aws",
		Properties: map[string]any{
			"network": map[string]any{
				"route_table": map[string]any{
					"routes": routesAny,
				},
			},
		},
	}
}

func TestTransitiveEgressFixtures(t *testing.T) {
	tests := []struct {
		name            string
		assets          []asset.Asset
		wantResult      string
		wantErr         bool
		wantPathType    string
		wantPort        int
		knownLimitation string
	}{
		{
			name: "writeup",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-mirror", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-svc", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-svc", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
				}),
			},
			wantResult:   "SAT",
			wantPathType: "transitive-egress",
			wantPort:     443,
		},
		{
			name: "remediated",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-mirror", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-mirror"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-svc", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-svc", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
				}),
			},
			wantResult: "UNSAT",
		},
		{
			name: "gated",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-relay", "vpc-ml", "subnet-tgw", []string{"sg-relay"}, map[string]string{"stave:role": "relay"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-relay", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-tgw", "vpc-ml", "rt-tgw", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-tgw", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-att-01"},
				}),
			},
			wantResult:   "EVIDENCE_GATED",
			wantPathType: "gated-egress",
			wantPort:     443,
		},
		{
			name: "partial-main-table",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-mirror", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-main", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-main", nil),
				routeTableAsset("rt-main", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-01"},
				}),
			},
			wantResult:   "SAT",
			wantPathType: "transitive-egress",
			wantPort:     443,
		},
		{
			name: "partial-precedence-sat-over-gated",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-gated", "vpc-ml", "subnet-tgw", []string{"sg-gated"}, map[string]string{"stave:role": "relay"}),
				hostAsset("i-sink", "vpc-ml", "subnet-nat", []string{"sg-sink"}, map[string]string{"stave:role": "mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-gated", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				sgAsset("sg-sink", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-tgw", "vpc-ml", "rt-tgw", nil),
				subnetAsset("subnet-nat", "vpc-ml", "rt-nat", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-tgw", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-att-01"},
				}),
				routeTableAsset("rt-nat", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
				}),
			},
			wantResult:   "SAT",
			wantPathType: "transitive-egress",
		},
		{
			name: "partial-gated-over-unsat",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-vpn", "vpc-ml", "subnet-vpn", []string{"sg-vpn"}, map[string]string{"stave:role": "vpn-gateway"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-vpn", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-vpn", "vpc-ml", "rt-vpn", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-vpn", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "vgw", TargetID: "vgw-01"},
				}),
			},
			wantResult:   "EVIDENCE_GATED",
			wantPathType: "gated-egress",
		},
		{
			name: "partial-unknown-target",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-appliance", "vpc-ml", "subnet-app", []string{"sg-app"}, map[string]string{"stave:role": "appliance"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-app", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-app", "vpc-ml", "rt-app", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-app", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "gwlbe", TargetID: "gwlbe-01"},
				}),
			},
			wantResult:   "EVIDENCE_GATED",
			wantPathType: "gated-egress",
		},
		{
			name: "partial-uppercase-target",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-mirror", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-svc", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-svc", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "NAT", TargetID: "nat-01"},
				}),
			},
			wantResult:   "SAT",
			wantPathType: "transitive-egress",
		},
		{
			name: "partial-no-isolated-host",
			assets: []asset.Asset{
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-mirror", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-svc", nil),
				routeTableAsset("rt-svc", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
				}),
			},
			wantErr: true,
		},
		{
			name: "partial-all-ports",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-mirror", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 0, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-svc", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAsset("rt-svc", []Route{
					{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
					{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
				}),
			},
			wantResult:   "SAT",
			wantPathType: "transitive-egress",
			wantPort:     0,
		},
		{
			// extractRouteTable does not read route state; a blackhole route
			// is indistinguishable from an active one. The prover reports SAT
			// even though the route cannot forward traffic.
			name: "partial-blackhole",
			assets: []asset.Asset{
				hostAsset("i-sandbox", "vpc-ml", "subnet-iso", []string{"sg-sandbox"}, map[string]string{"stave:network-zone": "isolated"}),
				hostAsset("i-mirror", "vpc-ml", "subnet-svc", []string{"sg-mirror"}, map[string]string{"stave:role": "package-mirror"}),
				sgAsset("sg-sandbox", nil),
				sgAsset("sg-mirror", []SGRule{{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-sandbox"}}),
				subnetAsset("subnet-iso", "vpc-ml", "rt-iso", nil),
				subnetAsset("subnet-svc", "vpc-ml", "rt-svc", nil),
				routeTableAsset("rt-iso", []Route{{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}}),
				routeTableAssetWithState("rt-svc", []map[string]any{
					{"destination": "10.0.0.0/16", "target_type": "local", "target_id": "local"},
					{"destination": "0.0.0.0/0", "target_type": "nat", "target_id": "nat-01", "state": "blackhole"},
				}),
			},
			wantResult:      "SAT",
			wantPathType:    "transitive-egress",
			knownLimitation: "extractRouteTable does not read route state; blackhole routes treated as active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := BuildGraph([]asset.Snapshot{{Assets: tt.assets}})
			result, err := g.ProveTransitiveEgress()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Result != tt.wantResult {
				t.Fatalf("expected %s, got %s", tt.wantResult, result.Result)
			}
			if tt.wantPathType != "" {
				if result.Counterexample == nil {
					t.Fatal("expected counterexample")
				}
				if result.Counterexample.PathType != tt.wantPathType {
					t.Errorf("expected path type %s, got %s", tt.wantPathType, result.Counterexample.PathType)
				}
			}
			if tt.wantPort != 0 && result.Counterexample != nil {
				if result.Counterexample.Port != tt.wantPort {
					t.Errorf("expected port %d, got %d", tt.wantPort, result.Counterexample.Port)
				}
			}
			if tt.knownLimitation != "" {
				t.Logf("KNOWN-LIMITATION: %s", tt.knownLimitation)
			}
		})
	}
}

func TestHost_IsCrossVPC(t *testing.T) {
	var nilHost *Host
	h1 := &Host{ID: "h1", VPCID: "vpc-1"}
	h2 := &Host{ID: "h2", VPCID: "vpc-2"}
	h1Same := &Host{ID: "h3", VPCID: "vpc-1"}
	noVPC := &Host{ID: "h4", VPCID: ""}

	if nilHost.IsCrossVPC(h1) {
		t.Error("nil host should not be cross-VPC")
	}
	if h1.IsCrossVPC(nilHost) {
		t.Error("host with nil other should not be cross-VPC")
	}
	if h1.IsCrossVPC(h1Same) {
		t.Error("hosts in same VPC should not be cross-VPC")
	}
	if h1.IsCrossVPC(noVPC) {
		t.Error("host with other missing VPC should not be cross-VPC")
	}
	if noVPC.IsCrossVPC(h1) {
		t.Error("host missing VPC should not be cross-VPC")
	}
	if !h1.IsCrossVPC(h2) {
		t.Error("hosts in different VPCs should be cross-VPC")
	}
}

func TestHost_SameHost(t *testing.T) {
	var nilHost *Host
	h1 := &Host{ID: "i-1"}
	h1Clone := &Host{ID: "i-1", VPCID: "vpc-1"}
	h2 := &Host{ID: "i-2"}
	empty1 := &Host{ID: ""}
	empty2 := &Host{ID: ""}

	if nilHost.SameHost(h1) {
		t.Error("nil host should not be same host")
	}
	if h1.SameHost(nilHost) {
		t.Error("host with nil other should not be same host")
	}
	if !h1.SameHost(h1) {
		t.Error("identical host should be same host")
	}
	if !h1.SameHost(h1Clone) {
		t.Error("hosts with matching ID should be same host")
	}
	if h1.SameHost(h2) {
		t.Error("hosts with different IDs should not be same host")
	}
	if empty1.SameHost(empty2) {
		t.Error("hosts with empty ID should not be same host")
	}
	if h1.SameHost(empty1) {
		t.Error("host should not match empty ID host")
	}
}

func TestHost_SameVPC(t *testing.T) {
	var nilHost *Host
	h1 := &Host{ID: "h1", VPCID: "vpc-1"}
	h2 := &Host{ID: "h2", VPCID: "vpc-2"}
	h1Same := &Host{ID: "h3", VPCID: "vpc-1"}
	noVPC := &Host{ID: "h4", VPCID: ""}
	noVPC2 := &Host{ID: "h5", VPCID: ""}

	if nilHost.SameVPC(h1) {
		t.Error("nil host should not be same VPC")
	}
	if h1.SameVPC(nilHost) {
		t.Error("host with nil other should not be same VPC")
	}
	if !h1.SameVPC(h1Same) {
		t.Error("hosts with matching VPCID should be same VPC")
	}
	if h1.SameVPC(h2) {
		t.Error("hosts with different VPCID should not be same VPC")
	}
	if h1.SameVPC(noVPC) {
		t.Error("host with other missing VPC should not be same VPC")
	}
	if noVPC.SameVPC(h1) {
		t.Error("host missing VPC should not be same VPC")
	}
	if noVPC.SameVPC(noVPC2) {
		t.Error("hosts both missing VPC should not be same VPC")
	}
}

func TestHost_IsInternal(t *testing.T) {
	var nilHost *Host
	h1 := &Host{ID: "h1", VPCID: "vpc-1"}
	h1Clone := &Host{ID: "h1", VPCID: "vpc-2"}
	h2SameVPC := &Host{ID: "h2", VPCID: "vpc-1"}
	h3DiffVPC := &Host{ID: "h3", VPCID: "vpc-2"}
	noVPC1 := &Host{ID: "h4", VPCID: ""}
	noVPC2 := &Host{ID: "h5", VPCID: ""}
	empty1 := &Host{}
	empty2 := &Host{}

	if nilHost.IsInternal(h1) {
		t.Error("nil host should not be internal")
	}
	if h1.IsInternal(nilHost) {
		t.Error("host with nil other should not be internal")
	}
	if !h1.IsInternal(h1) {
		t.Error("identical host should be internal")
	}
	if !h1.IsInternal(h1Clone) {
		t.Error("hosts with matching ID should be internal")
	}
	if !h1.IsInternal(h2SameVPC) {
		t.Error("hosts in same VPC should be internal")
	}
	if h1.IsInternal(h3DiffVPC) {
		t.Error("different hosts in different VPCs should not be internal")
	}
	if h1.IsInternal(noVPC1) {
		t.Error("different host with no VPC should not be internal")
	}
	if noVPC1.IsInternal(noVPC2) {
		t.Error("different hosts both missing VPC should not be internal")
	}
	if empty1.IsInternal(empty2) {
		t.Error("two empty hosts without ID or VPC should not be internal")
	}
}

func TestHost_IsTrusted(t *testing.T) {
	var nilHost *Host
	dst := &Host{ID: "i-prod", Tags: map[string]string{"stave:environment": "production"}}
	prodRelay := &Host{ID: "i-prod-2", Tags: map[string]string{"stave:environment": "production"}}
	bastionRelay := &Host{ID: "i-bastion", Tags: map[string]string{"stave:role": "bastion"}}
	stagingRelay := &Host{ID: "i-staging", Tags: map[string]string{"stave:environment": "staging"}}
	devRelay := &Host{ID: "i-dev", Tags: map[string]string{"stave:environment": "development"}}
	untaggedRelay := &Host{ID: "i-unknown"}

	if nilHost.IsTrusted(dst) {
		t.Error("nil host should not be trusted")
	}
	if stagingRelay.IsTrusted(nil) {
		t.Error("staging host with nil destination should not be trusted")
	}
	if !dst.IsTrusted(dst) {
		t.Error("destination itself should be trusted via same host / loopback")
	}
	sameDstClone := &Host{ID: "i-prod"}
	if !sameDstClone.IsTrusted(dst) {
		t.Error("host matching destination ID should be trusted via same host")
	}
	if !prodRelay.IsTrusted(dst) {
		t.Error("production host should be trusted via operational environment")
	}
	if !bastionRelay.IsTrusted(dst) {
		t.Error("authorized bastion should be trusted via administrative role")
	}
	if stagingRelay.IsTrusted(dst) {
		t.Error("staging non-bastion host should not be trusted")
	}
	if devRelay.IsTrusted(dst) {
		t.Error("development non-bastion host should not be trusted")
	}
	if untaggedRelay.IsTrusted(dst) {
		t.Error("untagged non-bastion host should not be trusted")
	}

	// Multi-target checks (e.g. src checked against relay and dst)
	if stagingRelay.IsTrusted() {
		t.Error("untrusted host with no target specified should not be trusted")
	}
	if !prodRelay.IsTrusted() {
		t.Error("production host should be trusted even with no targets specified")
	}
	if !bastionRelay.IsTrusted() {
		t.Error("bastion host should be trusted even with no targets specified")
	}
	if stagingRelay.IsTrusted(devRelay, dst) {
		t.Error("staging host should not be trusted when matching neither target")
	}
	if !stagingRelay.IsTrusted(stagingRelay, dst) {
		t.Error("staging host matching first target should be trusted")
	}
	if !stagingRelay.IsTrusted(devRelay, stagingRelay) {
		t.Error("staging host matching second target should be trusted")
	}
	if stagingRelay.IsTrusted(devRelay, nil) {
		t.Error("staging host with unmatched targets including nil should not be trusted")
	}
	if !prodRelay.IsTrusted(devRelay, dst) {
		t.Error("production host should be trusted in multi-target check")
	}
	if !bastionRelay.IsTrusted(devRelay, dst) {
		t.Error("bastion host should be trusted in multi-target check")
	}
}

func TestHost_HasSecurityGroup(t *testing.T) {
	var nilHost *Host
	h := &Host{ID: "i-app", SGIDs: []string{"sg-app", "sg-common"}}
	emptyHost := &Host{ID: "i-bare"}

	if nilHost.HasSecurityGroup("sg-app") {
		t.Error("nil host should not have security group")
	}
	if h.HasSecurityGroup("") {
		t.Error("host should not match empty security group ID")
	}
	if !h.HasSecurityGroup("sg-app") {
		t.Error("host should have sg-app")
	}
	if !h.HasSecurityGroup("sg-common") {
		t.Error("host should have sg-common")
	}
	if h.HasSecurityGroup("sg-other") {
		t.Error("host should not have sg-other")
	}
	if emptyHost.HasSecurityGroup("sg-app") {
		t.Error("host with no security groups should return false")
	}
}

func TestHost_Environment(t *testing.T) {
	tests := []struct {
		name string
		host *Host
		want string
	}{
		{
			name: "production environment",
			host: &Host{
				ID:   "i-prod",
				Tags: map[string]string{"stave:environment": "production"},
			},
			want: "production",
		},
		{
			name: "development environment",
			host: &Host{
				ID:   "i-dev",
				Tags: map[string]string{"stave:environment": "development"},
			},
			want: "development",
		},
		{
			name: "untagged environment with other tags",
			host: &Host{
				ID:   "i-bastion",
				Tags: map[string]string{"stave:role": "bastion"},
			},
			want: "",
		},
		{
			name: "empty tags map",
			host: &Host{
				ID:   "i-empty",
				Tags: map[string]string{},
			},
			want: "",
		},
		{
			name: "nil tags map",
			host: &Host{
				ID: "i-nil-tags",
			},
			want: "",
		},
		{
			name: "nil host",
			host: nil,
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.host.Environment(); got != tc.want {
				t.Errorf("Host%+v.Environment() = %q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

func TestRoute_IsDefaultRoute(t *testing.T) {
	tests := []struct {
		name string
		r    Route
		want bool
	}{
		{
			name: "ipv4 default route",
			r:    Route{Destination: "0.0.0.0/0"},
			want: true,
		},
		{
			name: "ipv6 default route",
			r:    Route{Destination: "::/0"},
			want: true,
		},
		{
			name: "rfc1918 private subnet",
			r:    Route{Destination: "10.0.0.0/16"},
			want: false,
		},
		{
			name: "specific host route",
			r:    Route{Destination: "192.168.1.1/32"},
			want: false,
		},
		{
			name: "empty destination",
			r:    Route{Destination: ""},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.IsDefaultRoute(); got != tc.want {
				t.Errorf("Route{%q}.IsDefaultRoute() = %v, want %v", tc.r.Destination, got, tc.want)
			}
		})
	}
}

func TestRoute_IsInternetGateway(t *testing.T) {
	tests := []struct {
		name string
		r    Route
		want bool
	}{
		{
			name: "igw target",
			r:    Route{TargetType: "igw"},
			want: true,
		},
		{
			name: "nat target",
			r:    Route{TargetType: "nat"},
			want: false,
		},
		{
			name: "vpce target",
			r:    Route{TargetType: "vpce"},
			want: false,
		},
		{
			name: "local target",
			r:    Route{TargetType: "local"},
			want: false,
		},
		{
			name: "empty target",
			r:    Route{TargetType: ""},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.IsInternetGateway(); got != tc.want {
				t.Errorf("Route{TargetType: %q}.IsInternetGateway() = %v, want %v", tc.r.TargetType, got, tc.want)
			}
		})
	}
}

func TestRoute_ClassifyTarget(t *testing.T) {
	tests := []struct {
		name       string
		route      Route
		wantClass  routeTargetClass
		wantReason string
	}{
		{
			name:       "nat sink target",
			route:      Route{TargetType: "nat"},
			wantClass:  routeSink,
			wantReason: "",
		},
		{
			name:       "igw sink target",
			route:      Route{TargetType: "igw"},
			wantClass:  routeSink,
			wantReason: "",
		},
		{
			name:       "eigw sink target",
			route:      Route{TargetType: "eigw"},
			wantClass:  routeSink,
			wantReason: "",
		},
		{
			name:       "local non-sink target",
			route:      Route{TargetType: "local"},
			wantClass:  routeNonSink,
			wantReason: "",
		},
		{
			name:       "tgw gated target",
			route:      Route{TargetType: "tgw"},
			wantClass:  routeGated,
			wantReason: "TGW route table not resolved",
		},
		{
			name:       "vgw gated target",
			route:      Route{TargetType: "vgw"},
			wantClass:  routeGated,
			wantReason: "on-premises egress not observable",
		},
		{
			name:       "vpce gated target",
			route:      Route{TargetType: "vpce"},
			wantClass:  routeGated,
			wantReason: "firewall policy not evaluated",
		},
		{
			name:       "instance gated target",
			route:      Route{TargetType: "instance"},
			wantClass:  routeGated,
			wantReason: "NAT instance or appliance forwarding not observable",
		},
		{
			name:       "eni gated target",
			route:      Route{TargetType: "eni"},
			wantClass:  routeGated,
			wantReason: "NAT instance or appliance forwarding not observable",
		},
		{
			name:       "unrecognized target",
			route:      Route{TargetType: "peer"},
			wantClass:  routeGated,
			wantReason: "unrecognized route target",
		},
		{
			name:       "empty target",
			route:      Route{TargetType: ""},
			wantClass:  routeGated,
			wantReason: "unrecognized route target",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.route.ClassifyTarget()
			if got.Class != tc.wantClass || got.Reason != tc.wantReason {
				t.Errorf("Route{%+v}.ClassifyTarget() = (%v, %q), want (%v, %q)",
					tc.route, got.Class, got.Reason, tc.wantClass, tc.wantReason)
			}
		})
	}
}

func TestRoute_Target(t *testing.T) {
	tests := []struct {
		name  string
		route Route
		want  string
	}{
		{
			name:  "both type and id present",
			route: Route{TargetType: "nat", TargetID: "nat-01"},
			want:  "nat:nat-01",
		},
		{
			name:  "igw target",
			route: Route{TargetType: "igw", TargetID: "igw-prod"},
			want:  "igw:igw-prod",
		},
		{
			name:  "local target with matching id",
			route: Route{TargetType: "local", TargetID: "local"},
			want:  "local:local",
		},
		{
			name:  "target type only",
			route: Route{TargetType: "nat", TargetID: ""},
			want:  "nat",
		},
		{
			name:  "empty target",
			route: Route{TargetType: "", TargetID: ""},
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.route.Target(); got != tc.want {
				t.Errorf("Route{%+v}.Target() = %q, want %q", tc.route, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsInternetIngress(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		want bool
	}{
		{
			name: "ipv4 internet ingress",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			want: true,
		},
		{
			name: "ipv6 internet ingress",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "::/0"},
			want: true,
		},
		{
			name: "ipv4 egress to internet",
			rule: SGRule{Direction: "egress", SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			want: false,
		},
		{
			name: "ingress private cidr",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "10.0.0.0/16"},
			want: false,
		},
		{
			name: "ingress sg reference",
			rule: SGRule{Direction: "ingress", SourceType: "sg", SourceValue: "sg-12345"},
			want: false,
		},
		{
			name: "ingress empty cidr",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: ""},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.IsInternetIngress(); got != tc.want {
				t.Errorf("SGRule{%+v}.IsInternetIngress() = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsInternetIngressOnPort(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		port int
		want bool
	}{
		{
			name: "matching port internet ingress",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "0.0.0.0/0", Port: 22},
			port: 22,
			want: true,
		},
		{
			name: "mismatched port internet ingress",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "0.0.0.0/0", Port: 443},
			port: 22,
			want: false,
		},
		{
			name: "matching port ipv6 internet ingress",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "::/0", Port: 22},
			port: 22,
			want: true,
		},
		{
			name: "matching port egress to internet",
			rule: SGRule{Direction: "egress", SourceType: "cidr", SourceValue: "0.0.0.0/0", Port: 22},
			port: 22,
			want: false,
		},
		{
			name: "matching port internal cidr",
			rule: SGRule{Direction: "ingress", SourceType: "cidr", SourceValue: "10.0.0.0/16", Port: 22},
			port: 22,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.IsInternetIngressOnPort(tc.port); got != tc.want {
				t.Errorf("SGRule{%+v}.IsInternetIngressOnPort(%d) = %v, want %v", tc.rule, tc.port, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsIngressOnPort(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		port int
		want bool
	}{
		{
			name: "matching port ingress",
			rule: SGRule{Direction: "ingress", Port: 80},
			port: 80,
			want: true,
		},
		{
			name: "mismatched port ingress",
			rule: SGRule{Direction: "ingress", Port: 80},
			port: 443,
			want: false,
		},
		{
			name: "matching port egress",
			rule: SGRule{Direction: "egress", Port: 80},
			port: 80,
			want: false,
		},
		{
			name: "mismatched port egress",
			rule: SGRule{Direction: "egress", Port: 80},
			port: 443,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.IsIngressOnPort(tc.port); got != tc.want {
				t.Errorf("SGRule{%+v}.IsIngressOnPort(%d) = %v, want %v", tc.rule, tc.port, got, tc.want)
			}
		})
	}
}

func TestSGRule_RuleSource(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		want string
	}{
		{
			name: "security group source",
			rule: SGRule{SourceType: "sg", SourceValue: "sg-12345"},
			want: "sg:sg-12345",
		},
		{
			name: "cidr source",
			rule: SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			want: "cidr:10.0.0.0/8",
		},
		{
			name: "empty source type fallback",
			rule: SGRule{SourceType: "", SourceValue: "10.0.0.0/8"},
			want: "10.0.0.0/8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.RuleSource(); got != tc.want {
				t.Errorf("SGRule{%+v}.RuleSource() = %q, want %q", tc.rule, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsIngress(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		want bool
	}{
		{
			name: "ingress direction",
			rule: SGRule{Direction: "ingress"},
			want: true,
		},
		{
			name: "egress direction",
			rule: SGRule{Direction: "egress"},
			want: false,
		},
		{
			name: "empty direction",
			rule: SGRule{Direction: ""},
			want: false,
		},
		{
			name: "other direction",
			rule: SGRule{Direction: "inbound"},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.IsIngress(); got != tc.want {
				t.Errorf("SGRule{%+v}.IsIngress() = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsCIDR(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		want bool
	}{
		{
			name: "cidr source type",
			rule: SGRule{SourceType: "cidr"},
			want: true,
		},
		{
			name: "sg source type",
			rule: SGRule{SourceType: "sg"},
			want: false,
		},
		{
			name: "empty source type",
			rule: SGRule{SourceType: ""},
			want: false,
		},
		{
			name: "other source type",
			rule: SGRule{SourceType: "prefix-list"},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.IsCIDR(); got != tc.want {
				t.Errorf("SGRule{%+v}.IsCIDR() = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsSecurityGroup(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		want bool
	}{
		{
			name: "sg source type",
			rule: SGRule{SourceType: "sg"},
			want: true,
		},
		{
			name: "cidr source type",
			rule: SGRule{SourceType: "cidr"},
			want: false,
		},
		{
			name: "empty source type",
			rule: SGRule{SourceType: ""},
			want: false,
		},
		{
			name: "other source type",
			rule: SGRule{SourceType: "prefix-list"},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.IsSecurityGroup(); got != tc.want {
				t.Errorf("SGRule{%+v}.IsSecurityGroup() = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestSGRule_IsInternal(t *testing.T) {
	sameVPC1 := &Host{ID: "i-app1", VPCID: "vpc-1", SGIDs: []string{"sg-app"}}
	sameVPC2 := &Host{ID: "i-app2", VPCID: "vpc-1", SGIDs: []string{"sg-db"}}
	diffVPC := &Host{ID: "i-ext", VPCID: "vpc-2", SGIDs: []string{"sg-app"}}

	tests := []struct {
		name         string
		rule         SGRule
		src          *Host
		dst          *Host
		wantOK       bool
		wantPathType string
	}{
		{
			name:         "matching sg reference",
			rule:         SGRule{SourceType: "sg", SourceValue: "sg-app"},
			src:          sameVPC1,
			dst:          sameVPC2,
			wantOK:       true,
			wantPathType: "sg-ref",
		},
		{
			name:         "unmatched sg reference",
			rule:         SGRule{SourceType: "sg", SourceValue: "sg-other"},
			src:          sameVPC1,
			dst:          sameVPC2,
			wantOK:       false,
			wantPathType: "",
		},
		{
			name:         "broad internal cidr same vpc",
			rule:         SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			src:          sameVPC1,
			dst:          sameVPC2,
			wantOK:       true,
			wantPathType: "cidr",
		},
		{
			name:         "broad internal cidr different vpc",
			rule:         SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			src:          diffVPC,
			dst:          sameVPC2,
			wantOK:       false,
			wantPathType: "",
		},
		{
			name:         "narrow cidr same vpc",
			rule:         SGRule{SourceType: "cidr", SourceValue: "10.0.1.0/24"},
			src:          sameVPC1,
			dst:          sameVPC2,
			wantOK:       false,
			wantPathType: "",
		},
		{
			name:         "nil src",
			rule:         SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			src:          nil,
			dst:          sameVPC2,
			wantOK:       false,
			wantPathType: "",
		},
		{
			name:         "nil dst",
			rule:         SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			src:          sameVPC1,
			dst:          nil,
			wantOK:       false,
			wantPathType: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOK, gotPathType := tc.rule.IsInternal(tc.src, tc.dst)
			if gotOK != tc.wantOK || gotPathType != tc.wantPathType {
				t.Errorf("SGRule{%+v}.IsInternal(%v, %v) = (%v, %q), want (%v, %q)",
					tc.rule, tc.src, tc.dst, gotOK, gotPathType, tc.wantOK, tc.wantPathType)
			}
		})
	}
}

func TestSGRule_HasBroadInternalCIDR(t *testing.T) {
	tests := []struct {
		name string
		rule SGRule
		want bool
	}{
		{
			name: "rfc1918 10/8",
			rule: SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			want: true,
		},
		{
			name: "rfc1918 172.16/12",
			rule: SGRule{SourceType: "cidr", SourceValue: "172.16.0.0/12"},
			want: true,
		},
		{
			name: "rfc1918 192.168/16",
			rule: SGRule{SourceType: "cidr", SourceValue: "192.168.0.0/16"},
			want: true,
		},
		{
			name: "default route ipv4 0.0.0.0/0",
			rule: SGRule{SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			want: true,
		},
		{
			name: "default route ipv6 ::/0",
			rule: SGRule{SourceType: "cidr", SourceValue: "::/0"},
			want: true,
		},
		{
			name: "narrow cidr",
			rule: SGRule{SourceType: "cidr", SourceValue: "10.0.1.0/24"},
			want: false,
		},
		{
			name: "sg reference with broad cidr value",
			rule: SGRule{SourceType: "sg", SourceValue: "10.0.0.0/8"},
			want: false,
		},
		{
			name: "empty rule",
			rule: SGRule{},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.HasBroadInternalCIDR(); got != tc.want {
				t.Errorf("SGRule{%+v}.HasBroadInternalCIDR() = %v, want %v", tc.rule, got, tc.want)
			}
		})
	}
}

func TestGraph_RouteBypassesFirewall(t *testing.T) {
	tests := []struct {
		name  string
		graph *Graph
		route Route
		want  bool
	}{
		{
			name: "igw route not in firewalls",
			graph: &Graph{
				Firewalls: map[string]bool{"vpce-fw-1": true},
			},
			route: Route{
				Destination: "0.0.0.0/0",
				TargetType:  "igw",
				TargetID:    "igw-main",
			},
			want: true,
		},
		{
			name: "igw route recognized as firewall endpoint",
			graph: &Graph{
				Firewalls: map[string]bool{"igw-fw": true},
			},
			route: Route{
				Destination: "0.0.0.0/0",
				TargetType:  "igw",
				TargetID:    "igw-fw",
			},
			want: false,
		},
		{
			name: "vpce route not in firewalls",
			graph: &Graph{
				Firewalls: map[string]bool{"vpce-fw-1": true},
			},
			route: Route{
				Destination: "0.0.0.0/0",
				TargetType:  "vpce",
				TargetID:    "vpce-s3",
			},
			want: false,
		},
		{
			name: "nat route",
			graph: &Graph{
				Firewalls: map[string]bool{"vpce-fw-1": true},
			},
			route: Route{
				Destination: "0.0.0.0/0",
				TargetType:  "nat",
				TargetID:    "nat-gw-1",
			},
			want: false,
		},
		{
			name: "local route",
			graph: &Graph{
				Firewalls: map[string]bool{},
			},
			route: Route{
				Destination: "10.0.0.0/16",
				TargetType:  "local",
				TargetID:    "local",
			},
			want: false,
		},
		{
			name:  "nil graph",
			graph: nil,
			route: Route{
				Destination: "0.0.0.0/0",
				TargetType:  "igw",
				TargetID:    "igw-main",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.graph.RouteBypassesFirewall(tc.route); got != tc.want {
				t.Errorf("Graph.RouteBypassesFirewall(%+v) = %v, want %v", tc.route, got, tc.want)
			}
		})
	}
}

func TestVPCPeering_Connects(t *testing.T) {
	peering := VPCPeering{
		PeeringID:    "pcx-12345",
		RequesterVPC: "vpc-requester",
		AccepterVPC:  "vpc-accepter",
	}

	tests := []struct {
		name    string
		peering VPCPeering
		vpc1    string
		vpc2    string
		want    bool
	}{
		{
			name:    "forward order matching requester and accepter",
			peering: peering,
			vpc1:    "vpc-requester",
			vpc2:    "vpc-accepter",
			want:    true,
		},
		{
			name:    "reverse order matching accepter and requester",
			peering: peering,
			vpc1:    "vpc-accepter",
			vpc2:    "vpc-requester",
			want:    true,
		},
		{
			name:    "requester matches but other VPC differs",
			peering: peering,
			vpc1:    "vpc-requester",
			vpc2:    "vpc-other",
			want:    false,
		},
		{
			name:    "accepter matches but other VPC differs",
			peering: peering,
			vpc1:    "vpc-other",
			vpc2:    "vpc-accepter",
			want:    false,
		},
		{
			name:    "neither VPC matches",
			peering: peering,
			vpc1:    "vpc-foo",
			vpc2:    "vpc-bar",
			want:    false,
		},
		{
			name:    "same VPC for both arguments",
			peering: peering,
			vpc1:    "vpc-requester",
			vpc2:    "vpc-requester",
			want:    false,
		},
		{
			name:    "empty first VPC",
			peering: peering,
			vpc1:    "",
			vpc2:    "vpc-accepter",
			want:    false,
		},
		{
			name:    "empty second VPC",
			peering: peering,
			vpc1:    "vpc-requester",
			vpc2:    "",
			want:    false,
		},
		{
			name:    "both VPCs empty",
			peering: peering,
			vpc1:    "",
			vpc2:    "",
			want:    false,
		},
		{
			name:    "empty peering with empty args",
			peering: VPCPeering{},
			vpc1:    "",
			vpc2:    "",
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.peering.Connects(tc.vpc1, tc.vpc2); got != tc.want {
				t.Errorf("VPCPeering%+v.Connects(%q, %q) = %v, want %v", tc.peering, tc.vpc1, tc.vpc2, got, tc.want)
			}
		})
	}
}

func TestSubnet_HasRouteTable(t *testing.T) {
	tests := []struct {
		name   string
		subnet *Subnet
		want   bool
	}{
		{
			name: "subnet with route table association",
			subnet: &Subnet{
				ID:           "subnet-01",
				VPCID:        "vpc-01",
				RouteTableID: "rt-01",
			},
			want: true,
		},
		{
			name: "subnet without route table association",
			subnet: &Subnet{
				ID:           "subnet-02",
				VPCID:        "vpc-01",
				RouteTableID: "",
			},
			want: false,
		},
		{
			name:   "empty subnet struct",
			subnet: &Subnet{},
			want:   false,
		},
		{
			name:   "nil subnet pointer",
			subnet: nil,
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.subnet.HasRouteTable(); got != tc.want {
				t.Errorf("Subnet%+v.HasRouteTable() = %v, want %v", tc.subnet, got, tc.want)
			}
		})
	}
}

func TestGraph_VPCsConnected(t *testing.T) {
	g := &Graph{
		Peerings: []VPCPeering{
			{RequesterVPC: "vpc-a", AccepterVPC: "vpc-b"},
		},
		TGWAttachments: []TGWAttachment{
			{TransitGatewayID: "tgw-1", VPCID: "vpc-c"},
			{TransitGatewayID: "tgw-1", VPCID: "vpc-d"},
		},
	}

	tests := []struct {
		name string
		g    *Graph
		vpc1 string
		vpc2 string
		want bool
	}{
		{
			name: "connected via peering forward",
			g:    g,
			vpc1: "vpc-a",
			vpc2: "vpc-b",
			want: true,
		},
		{
			name: "connected via peering reverse",
			g:    g,
			vpc1: "vpc-b",
			vpc2: "vpc-a",
			want: true,
		},
		{
			name: "connected via tgw",
			g:    g,
			vpc1: "vpc-c",
			vpc2: "vpc-d",
			want: true,
		},
		{
			name: "not connected across topologies",
			g:    g,
			vpc1: "vpc-a",
			vpc2: "vpc-c",
			want: false,
		},
		{
			name: "same vpc",
			g:    g,
			vpc1: "vpc-a",
			vpc2: "vpc-a",
			want: false,
		},
		{
			name: "empty vpc1",
			g:    g,
			vpc1: "",
			vpc2: "vpc-b",
			want: false,
		},
		{
			name: "empty vpc2",
			g:    g,
			vpc1: "vpc-a",
			vpc2: "",
			want: false,
		},
		{
			name: "nil graph",
			g:    nil,
			vpc1: "vpc-a",
			vpc2: "vpc-b",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.VPCsConnected(tc.vpc1, tc.vpc2); got != tc.want {
				t.Errorf("Graph.VPCsConnected(%q, %q) = %v, want %v", tc.vpc1, tc.vpc2, got, tc.want)
			}
		})
	}
}

func TestGraph_CanRouteCrossVPC(t *testing.T) {
	g := &Graph{
		Peerings: []VPCPeering{
			{RequesterVPC: "vpc-a", AccepterVPC: "vpc-b"},
		},
	}
	hostA := &Host{ID: "i-a", VPCID: "vpc-a"}
	hostB := &Host{ID: "i-b", VPCID: "vpc-b"}
	hostA2 := &Host{ID: "i-a2", VPCID: "vpc-a"}
	hostUnconnected := &Host{ID: "i-x", VPCID: "vpc-x"}

	tests := []struct {
		name string
		g    *Graph
		src  *Host
		dst  *Host
		want bool
	}{
		{
			name: "peered cross-vpc hosts",
			g:    g,
			src:  hostA,
			dst:  hostB,
			want: true,
		},
		{
			name: "same vpc hosts",
			g:    g,
			src:  hostA,
			dst:  hostA2,
			want: false,
		},
		{
			name: "unconnected vpc hosts",
			g:    g,
			src:  hostA,
			dst:  hostUnconnected,
			want: false,
		},
		{
			name: "nil src",
			g:    g,
			src:  nil,
			dst:  hostB,
			want: false,
		},
		{
			name: "nil dst",
			g:    g,
			src:  hostA,
			dst:  nil,
			want: false,
		},
		{
			name: "nil graph",
			g:    nil,
			src:  hostA,
			dst:  hostB,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.CanRouteCrossVPC(tc.src, tc.dst); got != tc.want {
				t.Errorf("Graph.CanRouteCrossVPC(%v, %v) = %v, want %v", tc.src, tc.dst, got, tc.want)
			}
		})
	}
}

func TestGraph_CanReach(t *testing.T) {
	hostA := &Host{ID: "i-a", VPCID: "vpc-a", SGIDs: []string{"sg-a"}}
	hostB := &Host{ID: "i-b", VPCID: "vpc-a", SGIDs: []string{"sg-b"}}
	hostC := &Host{ID: "i-c", VPCID: "vpc-c", SGIDs: []string{"sg-c"}}

	g := &Graph{
		Hosts: map[string]*Host{
			"i-a": hostA,
			"i-b": hostB,
			"i-c": hostC,
		},
		SGRules: map[string][]SGRule{
			"sg-b": {
				{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-a"},
				{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			},
			"sg-c": {
				{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			},
		},
		Peerings: []VPCPeering{
			{RequesterVPC: "vpc-a", AccepterVPC: "vpc-c"},
		},
	}

	tests := []struct {
		name         string
		g            *Graph
		src          *Host
		dst          *Host
		port         int
		wantOk       bool
		wantPathType string
	}{
		{
			name:         "same VPC via security group reference",
			g:            g,
			src:          hostA,
			dst:          hostB,
			port:         80,
			wantOk:       true,
			wantPathType: "sg-ref",
		},
		{
			name:         "same VPC via broad CIDR",
			g:            g,
			src:          hostA,
			dst:          hostB,
			port:         443,
			wantOk:       true,
			wantPathType: "cidr",
		},
		{
			name:         "cross-VPC peered via broad CIDR",
			g:            g,
			src:          hostA,
			dst:          hostC,
			port:         80,
			wantOk:       true,
			wantPathType: "cross-vpc",
		},
		{
			name:         "unmatched port",
			g:            g,
			src:          hostA,
			dst:          hostB,
			port:         22,
			wantOk:       false,
			wantPathType: "",
		},
		{
			name:         "nil graph",
			g:            nil,
			src:          hostA,
			dst:          hostB,
			port:         80,
			wantOk:       false,
			wantPathType: "",
		},
		{
			name:         "nil src",
			g:            g,
			src:          nil,
			dst:          hostB,
			port:         80,
			wantOk:       false,
			wantPathType: "",
		},
		{
			name:         "nil dst",
			g:            g,
			src:          hostA,
			dst:          nil,
			port:         80,
			wantOk:       false,
			wantPathType: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOk, gotPathType := tc.g.CanReach(tc.src, tc.dst, tc.port)
			if gotOk != tc.wantOk || gotPathType != tc.wantPathType {
				t.Errorf("CanReach(%v, %v, %d) = (%v, %q), want (%v, %q)",
					tc.src, tc.dst, tc.port, gotOk, gotPathType, tc.wantOk, tc.wantPathType)
			}
		})
	}
}

func TestGraph_SubnetForHost(t *testing.T) {
	subA := &Subnet{ID: "subnet-a", VPCID: "vpc-a", RouteTableID: "rt-a"}
	hostWithSubnet := &Host{ID: "i-a", SubnetID: "subnet-a"}
	hostWithUnknownSubnet := &Host{ID: "i-b", SubnetID: "subnet-unknown"}
	hostWithoutSubnet := &Host{ID: "i-c", SubnetID: ""}

	g := &Graph{
		Subnets: map[string]*Subnet{
			"subnet-a": subA,
		},
	}

	tests := []struct {
		name string
		g    *Graph
		host *Host
		want *Subnet
	}{
		{
			name: "host with matching subnet",
			g:    g,
			host: hostWithSubnet,
			want: subA,
		},
		{
			name: "host with unknown subnet",
			g:    g,
			host: hostWithUnknownSubnet,
			want: nil,
		},
		{
			name: "host with empty subnet ID",
			g:    g,
			host: hostWithoutSubnet,
			want: nil,
		},
		{
			name: "nil host",
			g:    g,
			host: nil,
			want: nil,
		},
		{
			name: "nil graph",
			g:    nil,
			host: hostWithSubnet,
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.SubnetForHost(tc.host); got != tc.want {
				t.Errorf("Graph.SubnetForHost(%v) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestGraph_RoutesForSubnet(t *testing.T) {
	routesA := []Route{
		{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
		{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"},
	}
	subWithRoutes := &Subnet{ID: "subnet-a", RouteTableID: "rt-a"}
	subWithoutRT := &Subnet{ID: "subnet-b", RouteTableID: ""}
	subWithUnknownRT := &Subnet{ID: "subnet-c", RouteTableID: "rt-unknown"}

	g := &Graph{
		Routes: map[string][]Route{
			"rt-a": routesA,
		},
	}

	tests := []struct {
		name   string
		g      *Graph
		subnet *Subnet
		want   []Route
	}{
		{
			name:   "subnet with associated routes",
			g:      g,
			subnet: subWithRoutes,
			want:   routesA,
		},
		{
			name:   "subnet without route table",
			g:      g,
			subnet: subWithoutRT,
			want:   nil,
		},
		{
			name:   "subnet with unknown route table",
			g:      g,
			subnet: subWithUnknownRT,
			want:   nil,
		},
		{
			name:   "nil subnet",
			g:      g,
			subnet: nil,
			want:   nil,
		},
		{
			name:   "nil graph",
			g:      nil,
			subnet: subWithRoutes,
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.g.RoutesForSubnet(tc.subnet)
			if len(got) != len(tc.want) {
				t.Errorf("Graph.RoutesForSubnet(%v) returned %d routes, want %d", tc.subnet, len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("Graph.RoutesForSubnet(%v)[%d] = %+v, want %+v", tc.subnet, i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestGraph_DefaultRouteForSubnet(t *testing.T) {
	defaultRoute := Route{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"}
	localRoute := Route{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}

	subWithDefault := &Subnet{ID: "subnet-a", RouteTableID: "rt-a"}
	subLocalOnly := &Subnet{ID: "subnet-b", RouteTableID: "rt-b"}
	subWithoutRT := &Subnet{ID: "subnet-c", RouteTableID: ""}

	g := &Graph{
		Routes: map[string][]Route{
			"rt-a": {localRoute, defaultRoute},
			"rt-b": {localRoute},
		},
	}

	tests := []struct {
		name      string
		g         *Graph
		subnet    *Subnet
		wantRoute Route
		wantOK    bool
	}{
		{
			name:      "subnet with default route",
			g:         g,
			subnet:    subWithDefault,
			wantRoute: defaultRoute,
			wantOK:    true,
		},
		{
			name:      "subnet with only local routes",
			g:         g,
			subnet:    subLocalOnly,
			wantRoute: Route{},
			wantOK:    false,
		},
		{
			name:      "subnet without route table",
			g:         g,
			subnet:    subWithoutRT,
			wantRoute: Route{},
			wantOK:    false,
		},
		{
			name:      "nil subnet",
			g:         g,
			subnet:    nil,
			wantRoute: Route{},
			wantOK:    false,
		},
		{
			name:      "nil graph",
			g:         nil,
			subnet:    subWithDefault,
			wantRoute: Route{},
			wantOK:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotRoute, gotOK := tc.g.DefaultRouteForSubnet(tc.subnet)
			if gotOK != tc.wantOK {
				t.Fatalf("DefaultRouteForSubnet() ok = %v, want %v", gotOK, tc.wantOK)
			}
			if gotRoute != tc.wantRoute {
				t.Errorf("DefaultRouteForSubnet() route = %+v, want %+v", gotRoute, tc.wantRoute)
			}
		})
	}
}

func TestSubnet_HasInternetEgress(t *testing.T) {
	subNAT := &Subnet{ID: "sub-nat", RouteTableID: "rt-nat"}
	subIGW := &Subnet{ID: "sub-igw", RouteTableID: "rt-igw"}
	subTGW := &Subnet{ID: "sub-tgw", RouteTableID: "rt-tgw"}
	subLocal := &Subnet{ID: "sub-local", RouteTableID: "rt-local"}
	subNoRT := &Subnet{ID: "sub-nort"}

	g := &Graph{
		Routes: map[string][]Route{
			"rt-nat":   {{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"}},
			"rt-igw":   {{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-01"}},
			"rt-tgw":   {{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-01"}},
			"rt-local": {{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}},
		},
	}

	tests := []struct {
		name string
		s    *Subnet
		g    *Graph
		want bool
	}{
		{"nil subnet", nil, g, false},
		{"nil graph", subNAT, nil, false},
		{"subnet with no route table", subNoRT, g, false},
		{"subnet with local default route only", subLocal, g, false},
		{"subnet with gated TGW default route", subTGW, g, false},
		{"subnet with NAT default route (sink)", subNAT, g, true},
		{"subnet with IGW default route (sink)", subIGW, g, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.HasInternetEgress(tc.g); got != tc.want {
				t.Errorf("Subnet.HasInternetEgress() = %v, want %v", got, tc.want)
			}
			if got := tc.g.SubnetHasInternetEgress(tc.s); got != tc.want {
				t.Errorf("Graph.SubnetHasInternetEgress() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSubnet_HasDefaultRoute(t *testing.T) {
	subNAT := &Subnet{ID: "sub-nat", RouteTableID: "rt-nat"}
	subIGW := &Subnet{ID: "sub-igw", RouteTableID: "rt-igw"}
	subTGW := &Subnet{ID: "sub-tgw", RouteTableID: "rt-tgw"}
	subLocal := &Subnet{ID: "sub-local", RouteTableID: "rt-local"}
	subNoRT := &Subnet{ID: "sub-nort"}

	g := &Graph{
		Routes: map[string][]Route{
			"rt-nat":   {{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"}},
			"rt-igw":   {{Destination: "::/0", TargetType: "igw", TargetID: "igw-01"}},
			"rt-tgw":   {{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-01"}},
			"rt-local": {{Destination: "10.0.0.0/16", TargetType: "local", TargetID: "local"}},
		},
	}

	tests := []struct {
		name string
		s    *Subnet
		g    *Graph
		want bool
	}{
		{"nil subnet", nil, g, false},
		{"nil graph", subNAT, nil, false},
		{"subnet with no route table", subNoRT, g, false},
		{"subnet with local non-default route", subLocal, g, false},
		{"subnet with IPv4 default route (nat)", subNAT, g, true},
		{"subnet with IPv6 default route (igw)", subIGW, g, true},
		{"subnet with TGW default route", subTGW, g, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.HasDefaultRoute(tc.g); got != tc.want {
				t.Errorf("Subnet.HasDefaultRoute() = %v, want %v", got, tc.want)
			}
			if got := tc.g.SubnetHasDefaultRoute(tc.s); got != tc.want {
				t.Errorf("Graph.SubnetHasDefaultRoute() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGraph_IsPubliclyAccessible(t *testing.T) {
	hostIPv4 := &Host{ID: "i-ipv4", SGIDs: []string{"sg-ipv4"}}
	hostIPv6 := &Host{ID: "i-ipv6", SGIDs: []string{"sg-ipv6"}}
	hostWrongPort := &Host{ID: "i-wrong-port", SGIDs: []string{"sg-wrong-port"}}
	hostEgress := &Host{ID: "i-egress", SGIDs: []string{"sg-egress"}}
	hostPrivate := &Host{ID: "i-private", SGIDs: []string{"sg-private"}}
	hostSGRef := &Host{ID: "i-sgref", SGIDs: []string{"sg-ref"}}
	hostUnknownSG := &Host{ID: "i-unknown", SGIDs: []string{"sg-unknown"}}
	hostNoSGs := &Host{ID: "i-no-sgs", SGIDs: nil}

	g := &Graph{
		SGRules: map[string][]SGRule{
			"sg-ipv4": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			},
			"sg-ipv6": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "::/0"},
			},
			"sg-wrong-port": {
				{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			},
			"sg-egress": {
				{Direction: "egress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
			},
			"sg-private": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
			},
			"sg-ref": {
				{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
			},
		},
	}

	tests := []struct {
		name string
		g    *Graph
		host *Host
		port int
		want bool
	}{
		{
			name: "host with 0.0.0.0/0 ingress on matching port",
			g:    g,
			host: hostIPv4,
			port: 22,
			want: true,
		},
		{
			name: "host with ::/0 ingress on matching port",
			g:    g,
			host: hostIPv6,
			port: 22,
			want: true,
		},
		{
			name: "host with internet ingress on different port",
			g:    g,
			host: hostWrongPort,
			port: 22,
			want: false,
		},
		{
			name: "host with egress-only internet rule",
			g:    g,
			host: hostEgress,
			port: 22,
			want: false,
		},
		{
			name: "host with private CIDR ingress only",
			g:    g,
			host: hostPrivate,
			port: 22,
			want: false,
		},
		{
			name: "host with security group reference only",
			g:    g,
			host: hostSGRef,
			port: 22,
			want: false,
		},
		{
			name: "host with unknown security group ID",
			g:    g,
			host: hostUnknownSG,
			port: 22,
			want: false,
		},
		{
			name: "host without security groups",
			g:    g,
			host: hostNoSGs,
			port: 22,
			want: false,
		},
		{
			name: "nil host",
			g:    g,
			host: nil,
			port: 22,
			want: false,
		},
		{
			name: "nil graph",
			g:    nil,
			host: hostIPv4,
			port: 22,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.g.IsPubliclyAccessible(tc.host, tc.port); got != tc.want {
				t.Errorf("Graph.IsPubliclyAccessible(%v, %d) = %v, want %v", tc.host, tc.port, got, tc.want)
			}
		})
	}
}

func TestSGRule_Allows(t *testing.T) {
	srcSameVPC := &Host{ID: "i-src1", VPCID: "vpc-1", SGIDs: []string{"sg-client"}}
	dstSameVPC := &Host{ID: "i-dst1", VPCID: "vpc-1", SGIDs: []string{"sg-server"}}
	srcDiffVPC := &Host{ID: "i-src2", VPCID: "vpc-2", SGIDs: []string{"sg-client"}}
	srcOtherSG := &Host{ID: "i-src3", VPCID: "vpc-1", SGIDs: []string{"sg-other"}}

	sgRefRule := SGRule{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-client"}
	broadCIDRRule := SGRule{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "10.0.0.0/8"}
	narrowCIDRRule := SGRule{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "198.51.100.0/24"}

	tests := []struct {
		name         string
		rule         SGRule
		src          *Host
		dst          *Host
		crossVPC     bool
		wantAllowed  bool
		wantPathType string
	}{
		{
			name:         "sg reference with matching source SG",
			rule:         sgRefRule,
			src:          srcSameVPC,
			dst:          dstSameVPC,
			crossVPC:     false,
			wantAllowed:  true,
			wantPathType: "sg-ref",
		},
		{
			name:         "sg reference with non-matching source SG",
			rule:         sgRefRule,
			src:          srcOtherSG,
			dst:          dstSameVPC,
			crossVPC:     false,
			wantAllowed:  false,
			wantPathType: "",
		},
		{
			name:         "broad CIDR in same VPC",
			rule:         broadCIDRRule,
			src:          srcSameVPC,
			dst:          dstSameVPC,
			crossVPC:     false,
			wantAllowed:  true,
			wantPathType: "cidr",
		},
		{
			name:         "broad CIDR cross VPC with crossVPC true",
			rule:         broadCIDRRule,
			src:          srcDiffVPC,
			dst:          dstSameVPC,
			crossVPC:     true,
			wantAllowed:  true,
			wantPathType: "cross-vpc",
		},
		{
			name:         "broad CIDR cross VPC with crossVPC false",
			rule:         broadCIDRRule,
			src:          srcDiffVPC,
			dst:          dstSameVPC,
			crossVPC:     false,
			wantAllowed:  false,
			wantPathType: "",
		},
		{
			name:         "narrow CIDR in same VPC",
			rule:         narrowCIDRRule,
			src:          srcSameVPC,
			dst:          dstSameVPC,
			crossVPC:     false,
			wantAllowed:  false,
			wantPathType: "",
		},
		{
			name:         "narrow CIDR cross VPC with crossVPC true",
			rule:         narrowCIDRRule,
			src:          srcDiffVPC,
			dst:          dstSameVPC,
			crossVPC:     true,
			wantAllowed:  false,
			wantPathType: "",
		},
		{
			name:         "nil source host",
			rule:         broadCIDRRule,
			src:          nil,
			dst:          dstSameVPC,
			crossVPC:     true,
			wantAllowed:  false,
			wantPathType: "",
		},
		{
			name:         "nil destination host",
			rule:         broadCIDRRule,
			src:          srcSameVPC,
			dst:          nil,
			crossVPC:     false,
			wantAllowed:  false,
			wantPathType: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAllowed, gotPathType := tc.rule.Allows(tc.src, tc.dst, tc.crossVPC)
			if gotAllowed != tc.wantAllowed {
				t.Errorf("SGRule.Allows() allowed = %v, want %v", gotAllowed, tc.wantAllowed)
			}
			if gotPathType != tc.wantPathType {
				t.Errorf("SGRule.Allows() pathType = %q, want %q", gotPathType, tc.wantPathType)
			}
		})
	}
}

func TestRuleMatch_Explanation(t *testing.T) {
	src := &Host{ID: "i-src", VPCID: "vpc-1"}
	dst := &Host{ID: "i-dst", VPCID: "vpc-2"}

	tests := []struct {
		name     string
		match    *RuleMatch
		src      *Host
		dst      *Host
		wantText string
	}{
		{
			name: "cross-vpc path type",
			match: &RuleMatch{
				SecurityGroupID: "sg-target",
				RuleSource:      "10.0.0.0/8",
				PathType:        "cross-vpc",
				Port:            22,
			},
			src:      src,
			dst:      dst,
			wantText: "Host i-src (vpc:vpc-1) can SSH to production host i-dst (vpc:vpc-2) via VPC peering. Security group sg-target allows SSH from 10.0.0.0/8. No bastion in the path.",
		},
		{
			name: "external path type",
			match: &RuleMatch{
				SecurityGroupID: "sg-target",
				RuleSource:      "0.0.0.0/0",
				PathType:        "external",
				Port:            22,
			},
			src:      nil,
			dst:      dst,
			wantText: "Production host i-dst accepts SSH from the internet (0.0.0.0/0) on sg-target. No bastion in the path.",
		},
		{
			name: "default internal path type",
			match: &RuleMatch{
				SecurityGroupID: "sg-target",
				RuleSource:      "sg:sg-app",
				PathType:        "sg-ref",
				Port:            22,
			},
			src:      src,
			dst:      dst,
			wantText: "Host i-src can SSH to production host i-dst via sg-target allowing SSH from sg:sg-app. No bastion in the path.",
		},
		{
			name:     "nil match receiver",
			match:    nil,
			src:      src,
			dst:      dst,
			wantText: "",
		},
		{
			name: "nil src and dst hosts",
			match: &RuleMatch{
				SecurityGroupID: "sg-target",
				RuleSource:      "sg:sg-app",
				PathType:        "sg-ref",
				Port:            22,
			},
			src:      nil,
			dst:      nil,
			wantText: "Host  can SSH to production host  via sg-target allowing SSH from sg:sg-app. No bastion in the path.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.match.Explanation(tc.src, tc.dst)
			if got != tc.wantText {
				t.Errorf("Explanation() = %q, want %q", got, tc.wantText)
			}
		})
	}
}

func TestRuleMatch_Remediation(t *testing.T) {
	match := &RuleMatch{
		SecurityGroupID: "sg-target",
		RuleSource:      "0.0.0.0/0",
		PathType:        "cidr",
		Port:            22,
	}

	tests := []struct {
		name     string
		match    *RuleMatch
		bastions []*Host
		wantText string
	}{
		{
			name:     "with bastions",
			match:    match,
			bastions: []*Host{{ID: "i-bastion"}},
			wantText: "Remove SSH ingress rule (0.0.0.0/0) on sg-target. Replace with SSH from bastion SG only.",
		},
		{
			name:     "without bastions",
			match:    match,
			bastions: nil,
			wantText: "Remove SSH ingress rule (0.0.0.0/0) on sg-target.",
		},
		{
			name: "external path type",
			match: &RuleMatch{
				SecurityGroupID: "sg-target",
				RuleSource:      "0.0.0.0/0",
				PathType:        "external",
				Port:            22,
			},
			bastions: nil,
			wantText: "Remove SSH ingress from 0.0.0.0/0 on sg-target. Restrict to bastion SG reference only.",
		},
		{
			name:     "nil match receiver",
			match:    nil,
			bastions: []*Host{{ID: "i-bastion"}},
			wantText: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.match.Remediation(tc.bastions)
			if got != tc.wantText {
				t.Errorf("Remediation() = %q, want %q", got, tc.wantText)
			}
		})
	}
}

func TestRuleMatch_SSHPath(t *testing.T) {
	match := &RuleMatch{
		SecurityGroupID: "sg-target",
		RuleSource:      "10.0.0.0/8",
		PathType:        "cidr",
		Port:            22,
	}

	t.Run("populates all fields when match is non-nil", func(t *testing.T) {
		got := match.SSHPath("i-src", "i-dst")
		want := SSHPath{
			Source:      "i-src",
			Destination: "i-dst",
			Port:        22,
			PathType:    "cidr",
			RuleSG:      "sg-target",
			RuleSource:  "10.0.0.0/8",
		}
		if got != want {
			t.Errorf("SSHPath() = %+v, want %+v", got, want)
		}
	})

	t.Run("handles nil receiver safely", func(t *testing.T) {
		var nilMatch *RuleMatch
		got := nilMatch.SSHPath("i-src", "i-dst")
		want := SSHPath{
			Source:      "i-src",
			Destination: "i-dst",
		}
		if got != want {
			t.Errorf("nil.SSHPath() = %+v, want %+v", got, want)
		}
	})
}

func TestGraph_allHosts(t *testing.T) {
	t.Run("returns all hosts when graph is non-nil", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{
				"h1": {ID: "h1"},
				"h2": {ID: "h2"},
			},
		}
		hosts := g.allHosts()
		if len(hosts) != 2 {
			t.Fatalf("allHosts() returned %d hosts, want 2", len(hosts))
		}
	})

	t.Run("returns nil when graph is nil", func(t *testing.T) {
		var nilGraph *Graph
		if got := nilGraph.allHosts(); got != nil {
			t.Errorf("nil.allHosts() = %v, want nil", got)
		}
	})
}

func Test_extractTags(t *testing.T) {
	t.Run("extracts and lowers string tags", func(t *testing.T) {
		props := map[string]any{
			"tags": map[string]any{
				"Environment": "Production",
				"Role":        "BASTION",
				"Invalid":     12345,
			},
		}
		got := extractTags(props)
		if got["Environment"] != "production" {
			t.Errorf("expected production, got %q", got["Environment"])
		}
		if got["Role"] != "bastion" {
			t.Errorf("expected bastion, got %q", got["Role"])
		}
		if _, exists := got["Invalid"]; exists {
			t.Errorf("expected non-string tag to be skipped, got %v", got["Invalid"])
		}
	})

	t.Run("returns empty non-nil map when tags key is missing or non-map", func(t *testing.T) {
		got := extractTags(map[string]any{"tags": "not-a-map"})
		if got == nil || len(got) != 0 {
			t.Errorf("expected empty non-nil map, got %v", got)
		}

		gotNil := extractTags(nil)
		if gotNil == nil || len(gotNil) != 0 {
			t.Errorf("expected empty non-nil map for nil props, got %v", gotNil)
		}
	})
}

func Test_extractStringSlice(t *testing.T) {
	t.Run("extracts string slice from map", func(t *testing.T) {
		props := map[string]any{
			"endpoints": []any{"vpce-1", "vpce-2", 999, "vpce-3"},
		}
		got := extractStringSlice(props, "endpoints")
		want := []string{"vpce-1", "vpce-2", "vpce-3"}
		if !slices.Equal(got, want) {
			t.Errorf("extractStringSlice = %v, want %v", got, want)
		}
	})

	t.Run("returns nil for missing key or nil map or invalid type", func(t *testing.T) {
		if got := extractStringSlice(nil, "key"); got != nil {
			t.Errorf("expected nil for nil map, got %v", got)
		}
		if got := extractStringSlice(map[string]any{}, "missing"); got != nil {
			t.Errorf("expected nil for missing key, got %v", got)
		}
		if got := extractStringSlice(map[string]any{"key": "not-a-slice"}, "key"); got != nil {
			t.Errorf("expected nil for non-slice, got %v", got)
		}
	})
}

func Test_stringProp(t *testing.T) {
	t.Run("returns string when key exists and is string", func(t *testing.T) {
		props := map[string]any{"vpc_id": "vpc-12345", "count": 42}
		if got := stringProp(props, "vpc_id"); got != "vpc-12345" {
			t.Errorf("stringProp = %q, want vpc-12345", got)
		}
	})

	t.Run("returns empty string when key is missing, nil map, or not a string", func(t *testing.T) {
		props := map[string]any{"count": 42}
		if got := stringProp(props, "missing"); got != "" {
			t.Errorf("expected empty string for missing key, got %q", got)
		}
		if got := stringProp(props, "count"); got != "" {
			t.Errorf("expected empty string for non-string, got %q", got)
		}
		if got := stringProp(nil, "key"); got != "" {
			t.Errorf("expected empty string for nil map, got %q", got)
		}
	})
}

func TestBuildGraph_EmptyAssetType(t *testing.T) {
	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{ID: "empty-type", Type: ""},
			},
		},
	}
	g := BuildGraph(snapshots)
	if len(g.Hosts) != 0 || len(g.Subnets) != 0 || len(g.Routes) != 0 {
		t.Errorf("expected empty graph for asset with empty type, got %+v", g)
	}
}

func Test_parseRoute(t *testing.T) {
	rm := map[string]any{
		"destination": "0.0.0.0/0",
		"target_type": "IGW",
		"target_id":   "igw-12345",
	}
	route := parseRoute(rm)
	if route.Destination != "0.0.0.0/0" {
		t.Errorf("expected 0.0.0.0/0, got %q", route.Destination)
	}
	if route.TargetType != "igw" {
		t.Errorf("expected lowered target type 'igw', got %q", route.TargetType)
	}
	if route.TargetID != "igw-12345" {
		t.Errorf("expected igw-12345, got %q", route.TargetID)
	}
}

func Test_parseSGRule(t *testing.T) {
	rm := map[string]any{
		"direction":    "ingress",
		"protocol":     "tcp",
		"source_type":  "cidr",
		"source_value": "10.0.0.0/8",
		"from_port":    float64(443),
	}
	rule := parseSGRule(rm)
	if rule.Direction != "ingress" {
		t.Errorf("expected ingress, got %q", rule.Direction)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("expected tcp, got %q", rule.Protocol)
	}
	if rule.SourceType != "cidr" {
		t.Errorf("expected cidr, got %q", rule.SourceType)
	}
	if rule.SourceValue != "10.0.0.0/8" {
		t.Errorf("expected 10.0.0.0/8, got %q", rule.SourceValue)
	}
	if rule.Port != 443 {
		t.Errorf("expected port 443, got %d", rule.Port)
	}
}

func TestGraph_Reachability(t *testing.T) {
	src := &Host{ID: "i-src", VPCID: "vpc-1", SGIDs: []string{"sg-client"}}
	dst := &Host{ID: "i-dst", VPCID: "vpc-1", SGIDs: []string{"sg-server"}}
	g := &Graph{
		Hosts: map[string]*Host{"i-src": src, "i-dst": dst},
		SGRules: map[string][]SGRule{
			"sg-server": {
				{
					Direction:   "ingress",
					Protocol:    "tcp",
					Port:        22,
					SourceType:  "sg",
					SourceValue: "sg-client",
				},
				{
					Direction:   "ingress",
					Protocol:    "tcp",
					Port:        80,
					SourceType:  "cidr",
					SourceValue: "10.0.0.0/8",
				},
			},
		},
	}

	t.Run("Reachability returns RuleMatch on matching port", func(t *testing.T) {
		match := g.Reachability(src, dst, 22)
		if match == nil {
			t.Fatal("expected non-nil RuleMatch")
		}
		if match.SecurityGroupID != "sg-server" {
			t.Errorf("SecurityGroupID = %q, want sg-server", match.SecurityGroupID)
		}
		if match.RuleSource != "sg:sg-client" {
			t.Errorf("RuleSource = %q, want sg:sg-client", match.RuleSource)
		}
		if match.PathType != "sg-ref" {
			t.Errorf("PathType = %q, want sg-ref", match.PathType)
		}
		if match.Port != 22 {
			t.Errorf("Port = %d, want 22", match.Port)
		}
	})

	t.Run("Reachability returns nil on unmatched port", func(t *testing.T) {
		if match := g.Reachability(src, dst, 443); match != nil {
			t.Errorf("expected nil RuleMatch for unmatched port, got %+v", match)
		}
	})

	t.Run("Reachability safe on nil receiver or hosts", func(t *testing.T) {
		var nilGraph *Graph
		if match := nilGraph.Reachability(src, dst, 22); match != nil {
			t.Errorf("expected nil for nil graph, got %+v", match)
		}
		if match := g.Reachability(nil, dst, 22); match != nil {
			t.Errorf("expected nil for nil src, got %+v", match)
		}
		if match := g.Reachability(src, nil, 22); match != nil {
			t.Errorf("expected nil for nil dst, got %+v", match)
		}
	})

	t.Run("ReachabilityAnyPort returns first matching rule", func(t *testing.T) {
		match := g.ReachabilityAnyPort(src, dst)
		if match == nil {
			t.Fatal("expected non-nil RuleMatch")
		}
		if match.Port != 22 {
			t.Errorf("Port = %d, want 22", match.Port)
		}
	})

	t.Run("ReachabilityAnyPort returns nil when no rule matches", func(t *testing.T) {
		unrelated := &Host{ID: "i-other", VPCID: "vpc-99"}
		if match := g.ReachabilityAnyPort(unrelated, dst); match != nil {
			t.Errorf("expected nil RuleMatch, got %+v", match)
		}
		var nilGraph *Graph
		if match := nilGraph.ReachabilityAnyPort(src, dst); match != nil {
			t.Errorf("expected nil for nil graph, got %+v", match)
		}
	})
}

func TestGraph_findInternetRule(t *testing.T) {
	dst := &Host{ID: "i-dst", VPCID: "vpc-1", SGIDs: []string{"sg-public", "sg-private"}}
	g := &Graph{
		Hosts: map[string]*Host{"i-dst": dst},
		SGRules: map[string][]SGRule{
			"sg-public": {
				{
					Direction:   "ingress",
					Protocol:    "tcp",
					Port:        22,
					SourceType:  "cidr",
					SourceValue: "0.0.0.0/0",
				},
				{
					Direction:   "ingress",
					Protocol:    "tcp",
					Port:        80,
					SourceType:  "cidr",
					SourceValue: "::/0",
				},
			},
			"sg-private": {
				{
					Direction:   "ingress",
					Protocol:    "tcp",
					Port:        443,
					SourceType:  "cidr",
					SourceValue: "10.0.0.0/8",
				},
			},
		},
	}

	t.Run("matching port returns RuleMatch", func(t *testing.T) {
		match := g.findInternetRule(dst, 22)
		if match == nil {
			t.Fatal("expected non-nil RuleMatch")
		}
		if match.SecurityGroupID != "sg-public" {
			t.Errorf("SecurityGroupID = %q, want sg-public", match.SecurityGroupID)
		}
		if match.RuleSource != "0.0.0.0/0" {
			t.Errorf("RuleSource = %q, want 0.0.0.0/0", match.RuleSource)
		}
		if match.PathType != "external" {
			t.Errorf("PathType = %q, want external", match.PathType)
		}
		if match.Port != 22 {
			t.Errorf("Port = %d, want 22", match.Port)
		}
	})

	t.Run("matching IPv6 port returns RuleMatch", func(t *testing.T) {
		match := g.findInternetRule(dst, 80)
		if match == nil {
			t.Fatal("expected non-nil RuleMatch")
		}
		if match.RuleSource != "::/0" {
			t.Errorf("RuleSource = %q, want ::/0", match.RuleSource)
		}
	})

	t.Run("unmatched port returns nil", func(t *testing.T) {
		if match := g.findInternetRule(dst, 443); match != nil {
			t.Errorf("expected nil for non-internet port, got %+v", match)
		}
	})

	t.Run("nil receiver or host returns nil", func(t *testing.T) {
		var nilGraph *Graph
		if match := nilGraph.findInternetRule(dst, 22); match != nil {
			t.Errorf("expected nil for nil graph, got %+v", match)
		}
		if match := g.findInternetRule(nil, 22); match != nil {
			t.Errorf("expected nil for nil host, got %+v", match)
		}
		if match := nilGraph.findInternetRuleAnyPort(dst); match != nil {
			t.Errorf("expected nil for nil graph, got %+v", match)
		}
		if match := g.findInternetRuleAnyPort(nil); match != nil {
			t.Errorf("expected nil for nil host, got %+v", match)
		}
	})

	t.Run("findInternetRuleAnyPort returns first internet rule", func(t *testing.T) {
		match := g.findInternetRuleAnyPort(dst)
		if match == nil {
			t.Fatal("expected non-nil RuleMatch")
		}
		if match.Port != 22 {
			t.Errorf("Port = %d, want 22", match.Port)
		}
	})

	t.Run("findInternetRuleAnyPort returns nil when host has no internet ingress", func(t *testing.T) {
		privateHost := &Host{ID: "i-priv", VPCID: "vpc-1", SGIDs: []string{"sg-private"}}
		if match := g.findInternetRuleAnyPort(privateHost); match != nil {
			t.Errorf("expected nil RuleMatch, got %+v", match)
		}
	})

	t.Run("findInternetRulesMatching returns all matching rules", func(t *testing.T) {
		matches := g.findInternetRulesMatching(dst, SGRule.IsInternetIngress)
		if len(matches) != 2 {
			t.Fatalf("expected 2 matches, got %d", len(matches))
		}
		if matches[0].RuleSource != "0.0.0.0/0" || matches[0].Port != 22 {
			t.Errorf("matches[0] = %+v, want 0.0.0.0/0 port 22", matches[0])
		}
		if matches[1].RuleSource != "::/0" || matches[1].Port != 80 {
			t.Errorf("matches[1] = %+v, want ::/0 port 80", matches[1])
		}
	})

	t.Run("findInternetRulesMatching returns nil on nil graph or dst", func(t *testing.T) {
		var nilGraph *Graph
		if matches := nilGraph.findInternetRulesMatching(dst, SGRule.IsInternetIngress); matches != nil {
			t.Errorf("expected nil for nil graph, got %+v", matches)
		}
		if matches := g.findInternetRulesMatching(nil, SGRule.IsInternetIngress); matches != nil {
			t.Errorf("expected nil for nil dst, got %+v", matches)
		}
	})

	t.Run("enumerateExternalSSHPaths preserves IPv6 rule source", func(t *testing.T) {
		v4Paths := g.enumerateExternalSSHPaths(dst, 22)
		if len(v4Paths) != 1 {
			t.Fatalf("expected 1 IPv4 path, got %d", len(v4Paths))
		}
		if v4Paths[0].Source != "0.0.0.0/0" || v4Paths[0].RuleSource != "0.0.0.0/0" {
			t.Errorf("v4Paths[0] source = %q, want 0.0.0.0/0", v4Paths[0].Source)
		}

		v6Paths := g.enumerateExternalSSHPaths(dst, 80)
		if len(v6Paths) != 1 {
			t.Fatalf("expected 1 IPv6 path, got %d", len(v6Paths))
		}
		if v6Paths[0].Source != "::/0" || v6Paths[0].RuleSource != "::/0" {
			t.Errorf("v6Paths[0] source = %q, want ::/0", v6Paths[0].Source)
		}
	})
}

func Test_newRouteCounterexample(t *testing.T) {
	sub := &Subnet{
		ID:           "subnet-priv-01",
		VPCID:        "vpc-1",
		RouteTableID: "rt-priv-01",
	}
	route := Route{
		Destination: "0.0.0.0/0",
		TargetType:  "igw",
		TargetID:    "igw-01",
	}

	t.Run("populates Counterexample and RoutePath with evidence", func(t *testing.T) {
		ce := newRouteCounterexample(sub, route, "direct-igw", "expl", "remed")
		if ce.Source != "subnet-priv-01" {
			t.Errorf("Source = %q, want subnet-priv-01", ce.Source)
		}
		if ce.Destination != "igw-01" {
			t.Errorf("Destination = %q, want igw-01", ce.Destination)
		}
		if ce.PathType != "direct-igw" {
			t.Errorf("PathType = %q, want direct-igw", ce.PathType)
		}
		if ce.Explanation != "expl" || ce.Remediation != "remed" {
			t.Errorf("unexpected explanation/remediation: %q / %q", ce.Explanation, ce.Remediation)
		}
		if ce.RoutePath == nil {
			t.Fatal("expected non-nil RoutePath")
		}
		if ce.RoutePath.RouteTableID != "rt-priv-01" {
			t.Errorf("RouteTableID = %q, want rt-priv-01", ce.RoutePath.RouteTableID)
		}
		if ce.RoutePath.Destination != "0.0.0.0/0" {
			t.Errorf("RoutePath.Destination = %q, want 0.0.0.0/0", ce.RoutePath.Destination)
		}
	})

	t.Run("handles nil subnet gracefully", func(t *testing.T) {
		ce := newRouteCounterexample(nil, route, "direct-igw", "expl", "remed")
		if ce.Source != "" {
			t.Errorf("Source = %q, want empty", ce.Source)
		}
		if ce.Destination != "igw-01" {
			t.Errorf("Destination = %q, want igw-01", ce.Destination)
		}
		if ce.RoutePath != nil {
			t.Errorf("expected nil RoutePath for nil subnet, got %+v", ce.RoutePath)
		}
	})
}

func TestGraph_tgwVPCMap(t *testing.T) {
	t.Run("groups VPCs by transit gateway ID", func(t *testing.T) {
		g := &Graph{
			TGWAttachments: []TGWAttachment{
				{AttachmentID: "att-1", TransitGatewayID: "tgw-1", VPCID: "vpc-a"},
				{AttachmentID: "att-2", TransitGatewayID: "tgw-1", VPCID: "vpc-b"},
				{AttachmentID: "att-3", TransitGatewayID: "tgw-2", VPCID: "vpc-c"},
			},
		}
		m := g.tgwVPCMap()
		if len(m) != 2 {
			t.Fatalf("expected 2 TGWs, got %d", len(m))
		}
		if !slices.Equal(m["tgw-1"], []string{"vpc-a", "vpc-b"}) {
			t.Errorf("tgw-1 = %v, want [vpc-a vpc-b]", m["tgw-1"])
		}
		if !slices.Equal(m["tgw-2"], []string{"vpc-c"}) {
			t.Errorf("tgw-2 = %v, want [vpc-c]", m["tgw-2"])
		}
		if !g.vpcsConnectedViaTGW("vpc-a", "vpc-b") {
			t.Error("expected vpc-a and vpc-b to be connected via tgw-1")
		}
		if g.vpcsConnectedViaTGW("vpc-a", "vpc-c") {
			t.Error("expected vpc-a and vpc-c not to be connected across different tgws")
		}
	})

	t.Run("handles nil receiver or empty attachments", func(t *testing.T) {
		var nilGraph *Graph
		if m := nilGraph.tgwVPCMap(); m != nil {
			t.Errorf("expected nil for nil graph, got %v", m)
		}
		if nilGraph.vpcsConnectedViaTGW("vpc-a", "vpc-b") {
			t.Error("expected false for nil graph")
		}

		emptyGraph := &Graph{}
		if m := emptyGraph.tgwVPCMap(); len(m) != 0 {
			t.Errorf("expected empty map for empty attachments, got %v", m)
		}
		if emptyGraph.vpcsConnectedViaTGW("vpc-a", "vpc-b") {
			t.Error("expected false for empty attachments")
		}
		if emptyGraph.vpcsConnectedViaTGW("", "vpc-b") || emptyGraph.vpcsConnectedViaTGW("vpc-a", "") {
			t.Error("expected false for empty VPC IDs")
		}
	})
}

func Test_newTransitiveCounterexample(t *testing.T) {
	relay := &Host{ID: "i-relay", VPCID: "vpc-1"}
	dst := &Host{ID: "i-prod", VPCID: "vpc-1"}
	relayMatch := &RuleMatch{
		SecurityGroupID: "sg-prod",
		RuleSource:      "sg:sg-relay",
		PathType:        "sg-ref",
		Port:            22,
	}

	t.Run("formats two-hop path, explanation, and evidence", func(t *testing.T) {
		ce := newTransitiveCounterexample(
			"0.0.0.0/0",
			"internet",
			"Host i-relay is SSH-accessible from the internet and",
			relay, dst, 22, relayMatch,
			"remediation instruction",
		)
		if ce.Source != "0.0.0.0/0 -> i-relay" {
			t.Errorf("Source = %q, want 0.0.0.0/0 -> i-relay", ce.Source)
		}
		if ce.Destination != "i-prod" {
			t.Errorf("Destination = %q, want i-prod", ce.Destination)
		}
		if ce.PathType != "transitive" {
			t.Errorf("PathType = %q, want transitive", ce.PathType)
		}
		wantExpl := "Host i-relay is SSH-accessible from the internet and can reach production host i-prod on port 22. Two-hop path: internet -> i-relay -> i-prod."
		if ce.Explanation != wantExpl {
			t.Errorf("Explanation = %q, want %q", ce.Explanation, wantExpl)
		}
		if ce.Remediation != "remediation instruction" {
			t.Errorf("Remediation = %q, want remediation instruction", ce.Remediation)
		}
		if ce.RuleSG != "sg-prod" || ce.RuleSource != "sg:sg-relay" {
			t.Errorf("RuleSG / RuleSource = %q / %q, want sg-prod / sg:sg-relay", ce.RuleSG, ce.RuleSource)
		}
	})

	t.Run("handles nil relay or dst gracefully", func(t *testing.T) {
		ce := newTransitiveCounterexample("src", "src", "lead", nil, nil, 22, nil, "rem")
		if ce.Source != "src -> " {
			t.Errorf("Source = %q, want src -> ", ce.Source)
		}
		if ce.Destination != "" {
			t.Errorf("Destination = %q, want empty", ce.Destination)
		}
	})
}

func TestFormatPort(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{port: 0, want: "all"},
		{port: 22, want: "22"},
		{port: 80, want: "80"},
		{port: 443, want: "443"},
		{port: 8080, want: "8080"},
	}
	for _, tc := range tests {
		if got := FormatPort(tc.port); got != tc.want {
			t.Errorf("FormatPort(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestGraph_findFirstEgressPath(t *testing.T) {
	iso := &Host{ID: "i-iso", VPCID: "vpc-1", SGIDs: []string{"sg-iso"}}
	sinkHost := &Host{ID: "i-sink", VPCID: "vpc-1", SGIDs: []string{"sg-sink"}}
	otherHost := &Host{ID: "i-other", VPCID: "vpc-1", SGIDs: []string{"sg-other"}}

	g := &Graph{
		Hosts: map[string]*Host{"i-iso": iso, "i-sink": sinkHost, "i-other": otherHost},
		SGRules: map[string][]SGRule{
			"sg-sink": {
				{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-iso"},
			},
		},
	}

	sinkCandidate := egressCandidate{
		host:  sinkHost,
		route: Route{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-1"},
	}
	otherCandidate := egressCandidate{
		host:  otherHost,
		route: Route{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-1"},
	}

	t.Run("finds first matching path", func(t *testing.T) {
		gotIso, gotC, gotMatch := g.findFirstEgressPath([]*Host{iso}, []egressCandidate{otherCandidate, sinkCandidate})
		if gotMatch == nil {
			t.Fatal("expected non-nil match")
		}
		if gotIso != iso {
			t.Errorf("gotIso = %v, want %v", gotIso, iso)
		}
		if gotC.host != sinkHost {
			t.Errorf("gotC.host = %v, want %v", gotC.host, sinkHost)
		}
	})

	t.Run("returns nil match when no path exists", func(t *testing.T) {
		gotIso, _, gotMatch := g.findFirstEgressPath([]*Host{iso}, []egressCandidate{otherCandidate})
		if gotMatch != nil {
			t.Errorf("expected nil match, got %+v", gotMatch)
		}
		if gotIso != nil {
			t.Errorf("expected nil iso, got %v", gotIso)
		}
	})

	t.Run("handles nil graph gracefully", func(t *testing.T) {
		var nilGraph *Graph
		gotIso, _, gotMatch := nilGraph.findFirstEgressPath([]*Host{iso}, []egressCandidate{sinkCandidate})
		if gotMatch != nil || gotIso != nil {
			t.Errorf("expected nil for nil graph, got match=%+v, iso=%+v", gotMatch, gotIso)
		}
	})
}

func TestGraph_findHostEgressCandidatePath(t *testing.T) {
	iso := &Host{ID: "i-iso", VPCID: "vpc-1", SGIDs: []string{"sg-iso"}}
	sinkHost := &Host{ID: "i-sink", VPCID: "vpc-1", SGIDs: []string{"sg-sink"}}
	otherHost := &Host{ID: "i-other", VPCID: "vpc-1", SGIDs: []string{"sg-other"}}

	g := &Graph{
		Hosts: map[string]*Host{"i-iso": iso, "i-sink": sinkHost, "i-other": otherHost},
		SGRules: map[string][]SGRule{
			"sg-sink": {
				{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-iso"},
			},
		},
	}
	sinkCandidate := egressCandidate{
		host:  sinkHost,
		route: Route{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-1"},
	}
	otherCandidate := egressCandidate{
		host:  otherHost,
		route: Route{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-1"},
	}

	t.Run("handles nil receiver or nil host gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if _, match, ok := nilGraph.findHostEgressCandidatePath(iso, []egressCandidate{sinkCandidate}); ok || match != nil {
			t.Error("expected false, nil for nil graph")
		}
		if _, match, ok := g.findHostEgressCandidatePath(nil, []egressCandidate{sinkCandidate}); ok || match != nil {
			t.Error("expected false, nil for nil host")
		}
	})

	t.Run("finds first matching candidate", func(t *testing.T) {
		c, match, ok := g.findHostEgressCandidatePath(iso, []egressCandidate{otherCandidate, sinkCandidate})
		if !ok || match == nil {
			t.Fatal("expected ok=true, non-nil match")
		}
		if c.host != sinkHost {
			t.Errorf("c.host = %v, want %v", c.host, sinkHost)
		}
		if match.Port != 80 {
			t.Errorf("match.Port = %d, want 80", match.Port)
		}
	})

	t.Run("returns false when no candidate is reachable", func(t *testing.T) {
		_, match, ok := g.findHostEgressCandidatePath(iso, []egressCandidate{otherCandidate})
		if ok || match != nil {
			t.Errorf("expected ok=false, nil match, got ok=%v, match=%v", ok, match)
		}
	})
}

func Test_parseHost(t *testing.T) {
	t.Run("nil asset returns nil", func(t *testing.T) {
		if got := parseHost(nil); got != nil {
			t.Errorf("parseHost(nil) = %v, want nil", got)
		}
	})

	t.Run("parses valid host asset", func(t *testing.T) {
		a := &asset.Asset{
			ID: "i-0123456789abcdef0",
			Properties: map[string]any{
				"tags": map[string]any{
					"stave:environment": "production",
				},
				"compute": map[string]any{
					"instance": map[string]any{
						"vpc_id":          "vpc-100",
						"subnet_id":       "subnet-200",
						"private_ip":      "10.0.1.5",
						"public_ip":       "54.1.2.3",
						"security_groups": []any{"sg-1", "sg-2"},
					},
				},
			},
		}
		got := parseHost(a)
		if got == nil {
			t.Fatal("expected non-nil Host")
		}
		if got.ID != "i-0123456789abcdef0" {
			t.Errorf("got ID = %q, want i-0123456789abcdef0", got.ID)
		}
		if got.VPCID != "vpc-100" || got.SubnetID != "subnet-200" {
			t.Errorf("got VPCID/SubnetID = %s/%s, want vpc-100/subnet-200", got.VPCID, got.SubnetID)
		}
		if got.PrivateIP != "10.0.1.5" || got.PublicIP != "54.1.2.3" {
			t.Errorf("got IPs = %s/%s, want 10.0.1.5/54.1.2.3", got.PrivateIP, got.PublicIP)
		}
		if len(got.SGIDs) != 2 || got.SGIDs[0] != "sg-1" || got.SGIDs[1] != "sg-2" {
			t.Errorf("got SGIDs = %v, want [sg-1 sg-2]", got.SGIDs)
		}
		if got.Tags["stave:environment"] != "production" {
			t.Errorf("got Tags = %v, want stave:environment=production", got.Tags)
		}
	})
}

func Test_parsePeering(t *testing.T) {
	t.Run("nil asset returns empty peering", func(t *testing.T) {
		got := parsePeering(nil)
		if got != (VPCPeering{}) {
			t.Errorf("parsePeering(nil) = %+v, want empty", got)
		}
	})

	t.Run("parses valid peering asset", func(t *testing.T) {
		a := &asset.Asset{
			ID: "pcx-12345",
			Properties: map[string]any{
				"network": map[string]any{
					"peering": map[string]any{
						"requester_vpc": "vpc-a",
						"accepter_vpc":  "vpc-b",
					},
				},
			},
		}
		got := parsePeering(a)
		if got.PeeringID != "pcx-12345" || got.RequesterVPC != "vpc-a" || got.AccepterVPC != "vpc-b" {
			t.Errorf("got %+v, want PeeringID=pcx-12345, RequesterVPC=vpc-a, AccepterVPC=vpc-b", got)
		}
	})
}

func Test_parseSubnet(t *testing.T) {
	t.Run("nil asset returns nil", func(t *testing.T) {
		if got := parseSubnet(nil); got != nil {
			t.Errorf("parseSubnet(nil) = %v, want nil", got)
		}
	})

	t.Run("parses valid subnet asset", func(t *testing.T) {
		a := &asset.Asset{
			ID: "subnet-123",
			Properties: map[string]any{
				"tags": map[string]any{
					"stave:subnet-type": "private",
				},
				"network": map[string]any{
					"subnet": map[string]any{
						"vpc_id":         "vpc-1",
						"route_table_id": "rt-1",
					},
				},
			},
		}
		got := parseSubnet(a)
		if got == nil {
			t.Fatal("expected non-nil Subnet")
		}
		if got.ID != "subnet-123" || got.VPCID != "vpc-1" || got.RouteTableID != "rt-1" {
			t.Errorf("got %+v, want ID=subnet-123, VPCID=vpc-1, RouteTableID=rt-1", got)
		}
		if !got.IsPrivate() {
			t.Error("expected IsPrivate() to be true")
		}
	})
}

func Test_parseTGWAttachment(t *testing.T) {
	t.Run("nil asset returns false", func(t *testing.T) {
		got, ok := parseTGWAttachment(nil)
		if ok || got != (TGWAttachment{}) {
			t.Errorf("parseTGWAttachment(nil) = (%+v, %v), want empty, false", got, ok)
		}
	})

	t.Run("missing network/transit_gateway returns false", func(t *testing.T) {
		a := &asset.Asset{ID: "tgw-att-0"}
		got, ok := parseTGWAttachment(a)
		if ok || got != (TGWAttachment{}) {
			t.Errorf("parseTGWAttachment(missing) = (%+v, %v), want empty, false", got, ok)
		}
	})

	t.Run("parses valid attachment asset", func(t *testing.T) {
		a := &asset.Asset{
			ID: "tgw-att-123",
			Properties: map[string]any{
				"network": map[string]any{
					"transit_gateway": map[string]any{
						"transit_gateway_id": "tgw-999",
						"vpc_id":             "vpc-888",
					},
				},
			},
		}
		got, ok := parseTGWAttachment(a)
		if !ok {
			t.Fatal("expected ok = true")
		}
		if got.AttachmentID != "tgw-att-123" || got.TransitGatewayID != "tgw-999" || got.VPCID != "vpc-888" {
			t.Errorf("got %+v, want AttachmentID=tgw-att-123, TransitGatewayID=tgw-999, VPCID=vpc-888", got)
		}
	})
}

func Test_vacuousErr(t *testing.T) {
	t.Run("wraps ErrVacuousProof without params", func(t *testing.T) {
		err := vacuousErr("simple reason")
		if !errors.Is(err, ErrVacuousProof) {
			t.Errorf("expected errors.Is(err, ErrVacuousProof) to be true, got %v", err)
		}
		if got := err.Error(); got != "vacuous proof: simple reason" {
			t.Errorf("err.Error() = %q, want 'vacuous proof: simple reason'", got)
		}
	})

	t.Run("formats string with params", func(t *testing.T) {
		err := vacuousErr("subnet %s missing %s", "sub-1", "routes")
		if !errors.Is(err, ErrVacuousProof) {
			t.Errorf("expected errors.Is(err, ErrVacuousProof) to be true, got %v", err)
		}
		if got := err.Error(); got != "vacuous proof: subnet sub-1 missing routes" {
			t.Errorf("err.Error() = %q, want 'vacuous proof: subnet sub-1 missing routes'", got)
		}
	})
}

func Test_newProofResult(t *testing.T) {
	scope := map[string]int{"hosts": 5, "endpoints": 2}
	res := newProofResult("database-isolation", scope)
	if res.Property != "database-isolation" {
		t.Errorf("Property = %q, want database-isolation", res.Property)
	}
	if res.Scope["hosts"] != 5 || res.Scope["endpoints"] != 2 {
		t.Errorf("Scope mismatch: %+v", res.Scope)
	}
}

func Test_newBastionProofResult(t *testing.T) {
	res := newBastionProofResult("bastion-ssh", 10, 3)
	if res.Property != "bastion-ssh" {
		t.Errorf("Property = %q, want bastion-ssh", res.Property)
	}
	if res.ProductionHosts != 10 || res.BastionHosts != 3 {
		t.Errorf("got prod/bastion = %d/%d, want 10/3", res.ProductionHosts, res.BastionHosts)
	}
}

func Test_parseRouteTableRoutes(t *testing.T) {
	t.Run("nil asset returns empty string and nil routes", func(t *testing.T) {
		rtID, routes := parseRouteTableRoutes(nil)
		if rtID != "" || routes != nil {
			t.Errorf("parseRouteTableRoutes(nil) = (%q, %v), want empty, nil", rtID, routes)
		}
	})

	t.Run("missing network/route_table returns rtID and nil routes", func(t *testing.T) {
		a := &asset.Asset{ID: "rt-missing"}
		rtID, routes := parseRouteTableRoutes(a)
		if rtID != "rt-missing" || routes != nil {
			t.Errorf("parseRouteTableRoutes(missing) = (%q, %v), want 'rt-missing', nil", rtID, routes)
		}
	})

	t.Run("parses valid route table asset", func(t *testing.T) {
		a := &asset.Asset{
			ID: "rt-123",
			Properties: map[string]any{
				"network": map[string]any{
					"route_table": map[string]any{
						"routes": []any{
							map[string]any{
								"destination": "0.0.0.0/0",
								"target_type": "IGW",
								"target_id":   "igw-abc",
							},
							map[string]any{
								"destination": "10.0.0.0/16",
								"target_type": "local",
								"target_id":   "",
							},
						},
					},
				},
			},
		}
		rtID, routes := parseRouteTableRoutes(a)
		if rtID != "rt-123" {
			t.Errorf("rtID = %q, want 'rt-123'", rtID)
		}
		if len(routes) != 2 {
			t.Fatalf("len(routes) = %d, want 2", len(routes))
		}
		if routes[0].Destination != "0.0.0.0/0" || routes[0].TargetType != "igw" || routes[0].TargetID != "igw-abc" {
			t.Errorf("routes[0] = %+v, want destination 0.0.0.0/0, target_type igw, target_id igw-abc", routes[0])
		}
		if routes[1].Destination != "10.0.0.0/16" || routes[1].TargetType != "local" || routes[1].TargetID != "" {
			t.Errorf("routes[1] = %+v, want destination 10.0.0.0/16, target_type local", routes[1])
		}
	})
}

func Test_parseFirewallEndpoints(t *testing.T) {
	t.Run("nil asset returns nil", func(t *testing.T) {
		if got := parseFirewallEndpoints(nil); got != nil {
			t.Errorf("parseFirewallEndpoints(nil) = %v, want nil", got)
		}
	})

	t.Run("missing network/firewall returns nil", func(t *testing.T) {
		a := &asset.Asset{ID: "fw-missing"}
		if got := parseFirewallEndpoints(a); got != nil {
			t.Errorf("parseFirewallEndpoints(missing) = %v, want nil", got)
		}
	})

	t.Run("parses valid firewall asset endpoints", func(t *testing.T) {
		a := &asset.Asset{
			ID: "fw-1",
			Properties: map[string]any{
				"network": map[string]any{
					"firewall": map[string]any{
						"endpoints": []any{"vpce-1", "vpce-2"},
					},
				},
			},
		}
		got := parseFirewallEndpoints(a)
		if len(got) != 2 || got[0] != "vpce-1" || got[1] != "vpce-2" {
			t.Errorf("parseFirewallEndpoints = %v, want [vpce-1, vpce-2]", got)
		}
	})
}

func TestGraph_findCrossEnvBypass(t *testing.T) {
	prodHost := &Host{
		ID:    "i-prod",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-prod"},
		Tags:  map[string]string{"stave:environment": "production"},
	}
	devHost := &Host{
		ID:    "i-dev",
		VPCID: "vpc-dev",
		SGIDs: []string{"sg-dev"},
		Tags:  map[string]string{"stave:environment": "development"},
	}

	t.Run("handles nil graph gracefully", func(t *testing.T) {
		var nilGraph *Graph
		src, dst, match := nilGraph.findCrossEnvBypass([]*Host{prodHost}, []*Host{devHost})
		if src != nil || dst != nil || match != nil {
			t.Errorf("expected all nil, got src=%v, dst=%v, match=%v", src, dst, match)
		}
	})

	t.Run("returns nil when no cross-environment path exists", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-dev": devHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {},
				"sg-dev":  {},
			},
		}
		src, dst, match := g.findCrossEnvBypass([]*Host{prodHost}, []*Host{devHost})
		if src != nil || dst != nil || match != nil {
			t.Errorf("expected all nil, got src=%v, dst=%v, match=%v", src, dst, match)
		}
	})

	t.Run("finds prod to dev bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-dev": devHost},
			SGRules: map[string][]SGRule{
				"sg-dev": {
					{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-prod"},
				},
			},
		}
		src, dst, match := g.findCrossEnvBypass([]*Host{prodHost}, []*Host{devHost})
		if match == nil {
			t.Fatal("expected non-nil match")
		}
		if src != prodHost || dst != devHost {
			t.Errorf("got src=%v, dst=%v, want src=prodHost, dst=devHost", src, dst)
		}
	})

	t.Run("finds dev to prod bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-dev": devHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-dev"},
				},
			},
		}
		src, dst, match := g.findCrossEnvBypass([]*Host{prodHost}, []*Host{devHost})
		if match == nil {
			t.Fatal("expected non-nil match")
		}
		if src != devHost || dst != prodHost {
			t.Errorf("got src=%v, dst=%v, want src=devHost, dst=prodHost", src, dst)
		}
	})
}

func TestGraph_findAnyReachabilityPath(t *testing.T) {
	h1 := &Host{ID: "i-h1", SGIDs: []string{"sg-1"}}
	h2 := &Host{ID: "i-h2", SGIDs: []string{"sg-2"}}

	t.Run("handles nil receiver gracefully", func(t *testing.T) {
		var nilGraph *Graph
		src, dst, match := nilGraph.findAnyReachabilityPath([]*Host{h1}, []*Host{h2})
		if src != nil || dst != nil || match != nil {
			t.Errorf("expected all nil for nil graph, got src=%v, dst=%v, match=%v", src, dst, match)
		}
	})

	t.Run("handles empty source or destination slices", func(t *testing.T) {
		g := NewGraph()
		src, dst, match := g.findAnyReachabilityPath(nil, []*Host{h2})
		if src != nil || dst != nil || match != nil {
			t.Errorf("expected all nil for nil sources, got src=%v, dst=%v, match=%v", src, dst, match)
		}
		src, dst, match = g.findAnyReachabilityPath([]*Host{h1}, nil)
		if src != nil || dst != nil || match != nil {
			t.Errorf("expected all nil for nil destinations, got src=%v, dst=%v, match=%v", src, dst, match)
		}
	})

	t.Run("finds first reachability match between bipartite hosts", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-h1": h1, "i-h2": h2},
			SGRules: map[string][]SGRule{
				"sg-2": {
					{Direction: "ingress", Protocol: "tcp", Port: 8080, SourceType: "sg", SourceValue: "sg-1"},
				},
			},
		}
		src, dst, match := g.findAnyReachabilityPath([]*Host{h1}, []*Host{h2})
		if match == nil {
			t.Fatal("expected match, got nil")
		}
		if src != h1 || dst != h2 {
			t.Errorf("got src=%v, dst=%v, want h1, h2", src, dst)
		}
		if match.Port != 8080 {
			t.Errorf("match.Port = %d, want 8080", match.Port)
		}
	})
}

func Test_parseSGRules(t *testing.T) {
	t.Run("nil asset returns empty string and nil rules", func(t *testing.T) {
		sgID, rules := parseSGRules(nil)
		if sgID != "" || rules != nil {
			t.Errorf("parseSGRules(nil) = (%q, %v), want empty, nil", sgID, rules)
		}
	})

	t.Run("missing network/security_group returns sgID and nil rules", func(t *testing.T) {
		a := &asset.Asset{ID: "sg-missing"}
		sgID, rules := parseSGRules(a)
		if sgID != "sg-missing" || rules != nil {
			t.Errorf("parseSGRules(missing) = (%q, %v), want 'sg-missing', nil", sgID, rules)
		}
	})

	t.Run("parses valid security group asset rules", func(t *testing.T) {
		a := &asset.Asset{
			ID: "sg-123",
			Properties: map[string]any{
				"network": map[string]any{
					"security_group": map[string]any{
						"rules": []any{
							map[string]any{
								"direction":    "ingress",
								"protocol":     "tcp",
								"source_type":  "cidr",
								"source_value": "0.0.0.0/0",
								"from_port":    float64(22),
							},
						},
					},
				},
			},
		}
		sgID, rules := parseSGRules(a)
		if sgID != "sg-123" {
			t.Errorf("sgID = %q, want 'sg-123'", sgID)
		}
		if len(rules) != 1 {
			t.Fatalf("len(rules) = %d, want 1", len(rules))
		}
		if rules[0].Direction != "ingress" || rules[0].Port != 22 || rules[0].SourceValue != "0.0.0.0/0" {
			t.Errorf("rules[0] = %+v, want ingress port 22 cidr 0.0.0.0/0", rules[0])
		}
	})
}

func TestGraph_findDatabaseBypass(t *testing.T) {
	dbHost := &Host{
		ID:    "i-db",
		VPCID: "vpc-db",
		SGIDs: []string{"sg-db"},
		Tags:  map[string]string{"stave:tier": "database"},
	}
	appHost := &Host{
		ID:    "i-app",
		VPCID: "vpc-app",
		SGIDs: []string{"sg-app"},
		Tags:  map[string]string{"stave:tier": "app"},
	}

	t.Run("handles nil receiver or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce, reason := nilGraph.findDatabaseBypass(dbHost); ce != nil || reason != "" {
			t.Errorf("expected nil for nil graph, got %+v, %q", ce, reason)
		}
		g := &Graph{}
		if ce, reason := g.findDatabaseBypass(nil); ce != nil || reason != "" {
			t.Errorf("expected nil for nil dst, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when database host is isolated", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-db": dbHost, "i-app": appHost},
			SGRules: map[string][]SGRule{
				"sg-db":  {},
				"sg-app": {},
			},
		}
		if ce, reason := g.findDatabaseBypass(dbHost); ce != nil || reason != "" {
			t.Errorf("expected nil, got ce=%+v, reason=%q", ce, reason)
		}
	})

	t.Run("finds cross-VPC bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-db": dbHost, "i-app": appHost},
			SGRules: map[string][]SGRule{
				"sg-db": {
					{Direction: "ingress", Protocol: "tcp", Port: 5432, SourceType: "sg", SourceValue: "sg-app"},
				},
			},
		}
		ce, reason := g.findDatabaseBypass(dbHost)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-app" || ce.Destination != "i-db" || ce.Port != 5432 {
			t.Errorf("got ce=%+v, want Source=i-app, Destination=i-db, Port=5432", ce)
		}
		if reason != "Database isolation violated — a host outside the database VPC can reach a database host." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})

	t.Run("finds internet bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-db": dbHost},
			SGRules: map[string][]SGRule{
				"sg-db": {
					{Direction: "ingress", Protocol: "tcp", Port: 5432, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
				},
			},
		}
		ce, reason := g.findDatabaseBypass(dbHost)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "i-db" || ce.Port != 5432 {
			t.Errorf("got ce=%+v, want Destination=i-db, Port=5432", ce)
		}
		if reason != "Database isolation violated — database host is directly accessible from the internet." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})
}

func TestGraph_findSubnetFirewallBypass(t *testing.T) {
	sub := &Subnet{
		ID:           "subnet-priv-1",
		VPCID:        "vpc-1",
		RouteTableID: "rt-1",
		Tags:         map[string]string{"stave:subnet-type": "private"},
	}

	t.Run("handles nil receiver or nil subnet gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce := nilGraph.findSubnetFirewallBypass(sub); ce != nil {
			t.Errorf("expected nil for nil graph, got %+v", ce)
		}
		g := &Graph{}
		if ce := g.findSubnetFirewallBypass(nil); ce != nil {
			t.Errorf("expected nil for nil subnet, got %+v", ce)
		}
	})

	t.Run("returns nil when subnet has no default route", func(t *testing.T) {
		g := &Graph{
			Subnets: map[string]*Subnet{"subnet-priv-1": sub},
			Routes: map[string][]Route{
				"rt-1": {
					{Destination: "10.0.0.0/16", TargetType: "local"},
				},
			},
		}
		if ce := g.findSubnetFirewallBypass(sub); ce != nil {
			t.Errorf("expected nil for non-default route, got %+v", ce)
		}
	})

	t.Run("returns nil when default route routes through firewall", func(t *testing.T) {
		g := &Graph{
			Subnets: map[string]*Subnet{"subnet-priv-1": sub},
			Routes: map[string][]Route{
				"rt-1": {
					{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-fw"},
				},
			},
			Firewalls: map[string]bool{"igw-fw": true},
		}
		if ce := g.findSubnetFirewallBypass(sub); ce != nil {
			t.Errorf("expected nil when firewall protects route, got %+v", ce)
		}
	})

	t.Run("finds firewall bypass when default route targets IGW without firewall", func(t *testing.T) {
		g := &Graph{
			Subnets: map[string]*Subnet{"subnet-priv-1": sub},
			Routes: map[string][]Route{
				"rt-1": {
					{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-bypass"},
				},
			},
			Firewalls: map[string]bool{"other-fw": true},
		}
		ce := g.findSubnetFirewallBypass(sub)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "subnet-priv-1" || ce.Destination != "igw-bypass" || ce.PathType != "direct-igw" {
			t.Errorf("got ce=%+v, want Source=subnet-priv-1, Destination=igw-bypass, PathType=direct-igw", ce)
		}
		if ce.RoutePath == nil || ce.RoutePath.RouteTableID != "rt-1" || ce.RoutePath.Destination != "0.0.0.0/0" {
			t.Errorf("got RoutePath=%+v, want RouteTableID=rt-1, Destination=0.0.0.0/0", ce.RoutePath)
		}
	})
}

func Test_newFirewallBypassCounterexample(t *testing.T) {
	sub := &Subnet{ID: "subnet-priv-1", RouteTableID: "rt-1"}
	route := Route{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-bypass"}

	t.Run("returns nil for nil subnet", func(t *testing.T) {
		if ce := newFirewallBypassCounterexample(nil, route); ce != nil {
			t.Errorf("expected nil for nil subnet, got %+v", ce)
		}
	})

	t.Run("formats counterexample with direct-igw path and route evidence", func(t *testing.T) {
		ce := newFirewallBypassCounterexample(sub, route)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "subnet-priv-1" || ce.Destination != "igw-bypass" || ce.PathType != "direct-igw" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
		if ce.RoutePath == nil || ce.RoutePath.RouteTableID != "rt-1" || ce.RoutePath.Destination != "0.0.0.0/0" {
			t.Errorf("unexpected RoutePath: %+v", ce.RoutePath)
		}
		if !strings.Contains(ce.Explanation, "Subnet subnet-priv-1 has a 0.0.0.0/0 route to IGW igw-bypass") {
			t.Errorf("unexpected explanation: %q", ce.Explanation)
		}
		if !strings.Contains(ce.Remediation, "Change the 0.0.0.0/0 route in rt-1 to target a Network Firewall endpoint instead of igw-bypass.") {
			t.Errorf("unexpected remediation: %q", ce.Remediation)
		}
	})
}

func TestGraph_findHostBastionBypass(t *testing.T) {
	prodHost := &Host{
		ID:    "i-prod",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-prod"},
		Tags:  map[string]string{"stave:environment": "production"},
	}
	bastionHost := &Host{
		ID:    "i-bastion",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-bastion"},
		Tags:  map[string]string{"stave:role": "bastion"},
	}
	untrustedHost := &Host{
		ID:    "i-untrusted",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-untrusted"},
		Tags:  map[string]string{"stave:environment": "development"},
	}

	t.Run("handles nil receiver or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce, reason := nilGraph.findHostBastionBypass(prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for nil graph, got %+v, %q", ce, reason)
		}
		g := &Graph{}
		if ce, reason := g.findHostBastionBypass(nil, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for nil dst, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when only bastion can access production host", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-bastion": bastionHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-bastion"},
				},
			},
		}
		if ce, reason := g.findHostBastionBypass(prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil when bastion only, got %+v, %q", ce, reason)
		}
	})

	t.Run("finds internal bypass from untrusted host", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-untrusted": untrustedHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-untrusted"},
				},
			},
		}
		ce, reason := g.findHostBastionBypass(prodHost, 22, []*Host{bastionHost})
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-untrusted" || ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Source=i-untrusted, Destination=i-prod, Port=22", ce)
		}
		if reason != "Bastion bypass exists — a non-bastion host can SSH to production without traversing a bastion." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})

	t.Run("finds external internet bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
				},
			},
		}
		ce, reason := g.findHostBastionBypass(prodHost, 22, []*Host{bastionHost})
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Destination=i-prod, Port=22", ce)
		}
		if reason != "Bastion bypass exists — production host is directly SSH-accessible from the internet." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})
}

func TestGraph_findInternalBastionSSHBypass(t *testing.T) {
	prodHost := &Host{
		ID:    "i-prod",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-prod"},
		Tags:  map[string]string{"stave:environment": "production"},
	}
	bastionHost := &Host{
		ID:    "i-bastion",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-bastion"},
		Tags:  map[string]string{"stave:role": "bastion"},
	}
	untrustedHost := &Host{
		ID:    "i-untrusted",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-untrusted"},
		Tags:  map[string]string{"stave:environment": "development"},
	}

	t.Run("handles nil receiver, nil src, or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce, reason := nilGraph.findInternalBastionSSHBypass(untrustedHost, prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for nil graph, got %+v, %q", ce, reason)
		}
		g := &Graph{}
		if ce, reason := g.findInternalBastionSSHBypass(nil, prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for nil src, got %+v, %q", ce, reason)
		}
		if ce, reason := g.findInternalBastionSSHBypass(untrustedHost, nil, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for nil dst, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when src is trusted", func(t *testing.T) {
		g := &Graph{}
		// Bastion is trusted
		if ce, reason := g.findInternalBastionSSHBypass(bastionHost, prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for bastion host, got %+v, %q", ce, reason)
		}
		// Another prod host is trusted
		peerProd := &Host{ID: "i-peer-prod", Tags: map[string]string{"stave:environment": "production"}}
		if ce, reason := g.findInternalBastionSSHBypass(peerProd, prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil for peer production host, got %+v, %q", ce, reason)
		}
	})

	t.Run("finds internal bypass when untrusted host has reachability to production", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{
				"i-prod":      prodHost,
				"i-untrusted": untrustedHost,
			},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-untrusted"},
				},
			},
		}
		ce, reason := g.findInternalBastionSSHBypass(untrustedHost, prodHost, 22, []*Host{bastionHost})
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-untrusted" || ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Source=i-untrusted, Destination=i-prod, Port=22", ce)
		}
		if reason != "Bastion bypass exists — a non-bastion host can SSH to production without traversing a bastion." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})

	t.Run("returns nil when untrusted host cannot reach production on port", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{
				"i-prod":      prodHost,
				"i-untrusted": untrustedHost,
			},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-untrusted"},
				},
			},
		}
		if ce, reason := g.findInternalBastionSSHBypass(untrustedHost, prodHost, 22, []*Host{bastionHost}); ce != nil || reason != "" {
			t.Errorf("expected nil when port does not match, got %+v, %q", ce, reason)
		}
	})
}

func TestGraph_findHostTransitiveSSHBypass(t *testing.T) {
	prodHost := &Host{
		ID:    "i-prod",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-prod"},
		Tags:  map[string]string{"stave:environment": "production"},
	}
	relayHost := &Host{
		ID:    "i-relay",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-relay"},
		Tags:  map[string]string{"stave:environment": "development"},
	}
	internalHost := &Host{
		ID:    "i-internal",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-internal"},
		Tags:  map[string]string{"stave:environment": "development"},
	}

	t.Run("handles nil receiver or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce, reason := nilGraph.findHostTransitiveSSHBypass(prodHost, 22); ce != nil || reason != "" {
			t.Errorf("expected nil for nil graph, got %+v, %q", ce, reason)
		}
		g := &Graph{}
		if ce, reason := g.findHostTransitiveSSHBypass(nil, 22); ce != nil || reason != "" {
			t.Errorf("expected nil for nil dst, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when no relay can reach production host", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost},
			SGRules: map[string][]SGRule{
				"sg-prod":  {},
				"sg-relay": {},
			},
		}
		if ce, reason := g.findHostTransitiveSSHBypass(prodHost, 22); ce != nil || reason != "" {
			t.Errorf("expected nil when no relay path, got %+v, %q", ce, reason)
		}
	})

	t.Run("finds transitive internet bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-relay"},
				},
				"sg-relay": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
				},
			},
		}
		ce, reason := g.findHostTransitiveSSHBypass(prodHost, 22)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Destination=i-prod, Port=22", ce)
		}
		if reason != "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})

	t.Run("finds transitive internal bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost, "i-internal": internalHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-relay"},
				},
				"sg-relay": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-internal"},
				},
			},
		}
		ce, reason := g.findHostTransitiveSSHBypass(prodHost, 22)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Destination=i-prod, Port=22", ce)
		}
		if reason != "Transitive SSH path exists — a non-bastion host can relay SSH to production via an intermediate host." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})
}

func TestGraph_findRelayCandidateTransitiveSSHBypass(t *testing.T) {
	prodHost := &Host{
		ID:    "i-prod",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-prod"},
		Tags:  map[string]string{"stave:environment": "production"},
	}
	relayHost := &Host{
		ID:    "i-relay",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-relay"},
		Tags:  map[string]string{"stave:environment": "development"},
	}
	bastionHost := &Host{
		ID:    "i-bastion",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-bastion"},
		Tags:  map[string]string{"stave:role": "bastion"},
	}

	t.Run("handles nil receiver, nil relay, or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce, reason := nilGraph.findRelayCandidateTransitiveSSHBypass(relayHost, prodHost, 22); ce != nil || reason != "" {
			t.Errorf("expected nil for nil graph, got %+v, %q", ce, reason)
		}
		g := &Graph{}
		if ce, reason := g.findRelayCandidateTransitiveSSHBypass(nil, prodHost, 22); ce != nil || reason != "" {
			t.Errorf("expected nil for nil relay, got %+v, %q", ce, reason)
		}
		if ce, reason := g.findRelayCandidateTransitiveSSHBypass(relayHost, nil, 22); ce != nil || reason != "" {
			t.Errorf("expected nil for nil dst, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when relay is trusted", func(t *testing.T) {
		g := &Graph{}
		if ce, reason := g.findRelayCandidateTransitiveSSHBypass(bastionHost, prodHost, 22); ce != nil || reason != "" {
			t.Errorf("expected nil for bastion relay, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when relay cannot reach production on port", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-relay"},
				},
			},
		}
		if ce, reason := g.findRelayCandidateTransitiveSSHBypass(relayHost, prodHost, 22); ce != nil || reason != "" {
			t.Errorf("expected nil when port does not match, got %+v, %q", ce, reason)
		}
	})

	t.Run("finds transitive bypass when relay can reach production and is reachable from internet", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-relay"},
				},
				"sg-relay": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
				},
			},
		}
		ce, reason := g.findRelayCandidateTransitiveSSHBypass(relayHost, prodHost, 22)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Destination=i-prod, Port=22", ce)
		}
		if reason != "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})
}

func TestGraph_Prove(t *testing.T) {
	t.Run("handles nil graph gracefully", func(t *testing.T) {
		var nilGraph *Graph
		res, err := nilGraph.Prove("bastion-ssh", 22)
		if err == nil || res != nil {
			t.Errorf("expected error for nil graph, got res=%v, err=%v", res, err)
		}
	})

	t.Run("returns error on unknown property", func(t *testing.T) {
		g := &Graph{}
		res, err := g.Prove("unknown-property", 22)
		if err == nil || res != nil {
			t.Fatalf("expected error for unknown property, got res=%v, err=%v", res, err)
		}
		if !strings.Contains(err.Error(), "unknown property \"unknown-property\"") {
			t.Errorf("err = %q, want containing 'unknown property'", err.Error())
		}
	})

	t.Run("dispatches to all valid properties", func(t *testing.T) {
		g := &Graph{}
		properties := []string{
			"",
			"bastion-ssh",
			"prod-dev-isolation",
			"database-isolation",
			"firewall-mandatory",
			"transitive-ssh",
			"transitive-egress",
		}
		for _, prop := range properties {
			t.Run("property="+prop, func(t *testing.T) {
				// On an empty graph, all provers return a vacuous proof error.
				res, err := g.Prove(prop, 0)
				if res != nil {
					t.Errorf("expected nil result on empty graph, got %+v", res)
				}
				if !errors.Is(err, ErrVacuousProof) {
					t.Errorf("expected ErrVacuousProof, got %v", err)
				}
			})
		}
	})
}

func TestGraph_NilGuards(t *testing.T) {
	var nilGraph *Graph

	if got := nilGraph.PrivateSubnets(); got != nil {
		t.Errorf("nilGraph.PrivateSubnets() = %v, want nil", got)
	}
	if got := nilGraph.ProductionHosts(); got != nil {
		t.Errorf("nilGraph.ProductionHosts() = %v, want nil", got)
	}
	if got := nilGraph.BastionHosts(); got != nil {
		t.Errorf("nilGraph.BastionHosts() = %v, want nil", got)
	}
	if got := nilGraph.DevelopmentHosts(); got != nil {
		t.Errorf("nilGraph.DevelopmentHosts() = %v, want nil", got)
	}
	if got := nilGraph.DatabaseHosts(); got != nil {
		t.Errorf("nilGraph.DatabaseHosts() = %v, want nil", got)
	}
	if got := nilGraph.IsolatedHosts(); got != nil {
		t.Errorf("nilGraph.IsolatedHosts() = %v, want nil", got)
	}
}

func Test_newRuleMatch(t *testing.T) {
	match := newRuleMatch("sg-12345", "10.0.0.0/8", "cidr", 22)
	if match == nil {
		t.Fatal("expected non-nil RuleMatch")
	}
	if match.SecurityGroupID != "sg-12345" {
		t.Errorf("SecurityGroupID = %q, want sg-12345", match.SecurityGroupID)
	}
	if match.RuleSource != "10.0.0.0/8" {
		t.Errorf("RuleSource = %q, want 10.0.0.0/8", match.RuleSource)
	}
	if match.PathType != "cidr" {
		t.Errorf("PathType = %q, want cidr", match.PathType)
	}
	if match.Port != 22 {
		t.Errorf("Port = %d, want 22", match.Port)
	}
}

func TestGraph_findTransitiveInternalHostBypass(t *testing.T) {
	prodHost := &Host{
		ID:    "i-prod",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-prod"},
		Tags:  map[string]string{"stave:environment": "production"},
	}
	relayHost := &Host{
		ID:    "i-relay",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-relay"},
		Tags:  map[string]string{"stave:environment": "development"},
	}
	internalHost := &Host{
		ID:    "i-internal",
		VPCID: "vpc-prod",
		SGIDs: []string{"sg-internal"},
		Tags:  map[string]string{"stave:environment": "development"},
	}
	relayMatch := newRuleMatch("sg-prod", "sg:sg-relay", "sg-ref", 22)

	t.Run("handles nil receiver or arguments gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce := nilGraph.findTransitiveInternalHostBypass(relayHost, prodHost, 22, relayMatch); ce != nil {
			t.Errorf("expected nil for nil graph, got %+v", ce)
		}
		g := &Graph{}
		if ce := g.findTransitiveInternalHostBypass(nil, prodHost, 22, relayMatch); ce != nil {
			t.Errorf("expected nil for nil relay, got %+v", ce)
		}
		if ce := g.findTransitiveInternalHostBypass(relayHost, nil, 22, relayMatch); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := g.findTransitiveInternalHostBypass(relayHost, prodHost, 22, nil); ce != nil {
			t.Errorf("expected nil for nil relayMatch, got %+v", ce)
		}
	})

	t.Run("returns nil when no internal host can reach relay", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost, "i-internal": internalHost},
			SGRules: map[string][]SGRule{
				"sg-prod":  {},
				"sg-relay": {},
			},
		}
		if ce := g.findTransitiveInternalHostBypass(relayHost, prodHost, 22, relayMatch); ce != nil {
			t.Errorf("expected nil when no internal reachability, got %+v", ce)
		}
	})

	t.Run("finds internal host counterexample", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost, "i-internal": internalHost},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-relay"},
				},
				"sg-relay": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-internal"},
				},
			},
		}
		ce := g.findTransitiveInternalHostBypass(relayHost, prodHost, 22, relayMatch)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "i-prod" || ce.Port != 22 {
			t.Errorf("got ce=%+v, want Destination=i-prod, Port=22", ce)
		}
	})
}

func TestGraph_extractAsset(t *testing.T) {
	t.Run("handles nil receiver or nil asset gracefully", func(t *testing.T) {
		var nilGraph *Graph
		nilGraph.extractAsset(&asset.Asset{Type: kernel.AssetType(GraphTypes.Instance)})

		g := NewGraph()
		g.extractAsset(nil)
		g.extractAsset(&asset.Asset{})
		g.extractAsset(&asset.Asset{Type: kernel.AssetType("unknown_asset_type")})
		if len(g.Hosts) != 0 {
			t.Errorf("expected 0 hosts, got %d", len(g.Hosts))
		}
	})

	t.Run("dispatches known asset type to extractor", func(t *testing.T) {
		g := NewGraph()
		a := &asset.Asset{
			ID:   "i-test-1",
			Type: kernel.AssetType(GraphTypes.Instance),
			Properties: map[string]any{
				"compute": map[string]any{
					"instance": map[string]any{
						"vpc_id": "vpc-test",
					},
				},
			},
		}
		g.extractAsset(a)
		if h, ok := g.Hosts["i-test-1"]; !ok || h.VPCID != "vpc-test" {
			t.Errorf("host not extracted as expected: %+v", h)
		}
	})
}

func TestGraph_findTransitiveEgressBypass(t *testing.T) {
	isoHost := &Host{ID: "i-iso", SGIDs: []string{"sg-iso"}}
	sinkHost := &Host{ID: "i-sink", SGIDs: []string{"sg-sink"}}
	sinks := []egressCandidate{
		{
			host:   sinkHost,
			route:  Route{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-1"},
			target: RouteTarget{Class: routeSink, TargetID: "nat-1"},
		},
	}

	t.Run("handles nil receiver or empty candidates gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce := nilGraph.findTransitiveEgressBypass([]*Host{isoHost}, sinks); ce != nil {
			t.Errorf("expected nil for nil graph, got %+v", ce)
		}
		g := &Graph{}
		if ce := g.findTransitiveEgressBypass(nil, sinks); ce != nil {
			t.Errorf("expected nil for nil isolated hosts, got %+v", ce)
		}
		if ce := g.findTransitiveEgressBypass([]*Host{isoHost}, nil); ce != nil {
			t.Errorf("expected nil for nil sinks, got %+v", ce)
		}
	})

	t.Run("returns nil when no path reaches sink", func(t *testing.T) {
		g := &Graph{
			Hosts:   map[string]*Host{"i-iso": isoHost, "i-sink": sinkHost},
			SGRules: map[string][]SGRule{"sg-sink": {}},
		}
		if ce := g.findTransitiveEgressBypass([]*Host{isoHost}, sinks); ce != nil {
			t.Errorf("expected nil when no path, got %+v", ce)
		}
	})

	t.Run("returns counterexample when isolated host reaches sink", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-iso": isoHost, "i-sink": sinkHost},
			SGRules: map[string][]SGRule{
				"sg-sink": {
					{Direction: "ingress", Protocol: "tcp", Port: 443, SourceType: "sg", SourceValue: "sg-iso"},
				},
			},
		}
		ce := g.findTransitiveEgressBypass([]*Host{isoHost}, sinks)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.PathType != "transitive-egress" || ce.Source != "i-iso" || ce.Destination != "i-sink" || ce.Port != 443 {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})
}

func TestGraph_findTransitiveEgressGated(t *testing.T) {
	isoHost := &Host{ID: "i-iso", SGIDs: []string{"sg-iso"}}
	gatedHost := &Host{ID: "i-gated", SGIDs: []string{"sg-gated"}}
	gated := []egressCandidate{
		{
			host:   gatedHost,
			route:  Route{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-1"},
			target: RouteTarget{Class: routeGated, Reason: "TGW route table not resolved", TargetID: "tgw-1"},
		},
	}

	t.Run("handles nil receiver or empty candidates gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce := nilGraph.findTransitiveEgressGated([]*Host{isoHost}, gated); ce != nil {
			t.Errorf("expected nil for nil graph, got %+v", ce)
		}
		g := &Graph{}
		if ce := g.findTransitiveEgressGated(nil, gated); ce != nil {
			t.Errorf("expected nil for nil isolated hosts, got %+v", ce)
		}
		if ce := g.findTransitiveEgressGated([]*Host{isoHost}, nil); ce != nil {
			t.Errorf("expected nil for nil gated, got %+v", ce)
		}
	})

	t.Run("returns counterexample when isolated host reaches gated target", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-iso": isoHost, "i-gated": gatedHost},
			SGRules: map[string][]SGRule{
				"sg-gated": {
					{Direction: "ingress", Protocol: "tcp", Port: 80, SourceType: "sg", SourceValue: "sg-iso"},
				},
			},
		}
		ce := g.findTransitiveEgressGated([]*Host{isoHost}, gated)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.PathType != "gated-egress" || ce.Source != "i-iso" || ce.Destination != "i-gated" || ce.Port != 80 {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})
}

func Test_newEgressBypassCounterexample(t *testing.T) {
	iso := &Host{ID: "i-iso"}
	sink := egressCandidate{
		host:  &Host{ID: "i-sink"},
		route: Route{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
	}
	match := &RuleMatch{SecurityGroupID: "sg-sink", RuleSource: "sg-iso", Port: 443}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newEgressBypassCounterexample(nil, sink, match); ce != nil {
			t.Errorf("expected nil for nil iso, got %+v", ce)
		}
		if ce := newEgressBypassCounterexample(iso, egressCandidate{}, match); ce != nil {
			t.Errorf("expected nil for empty candidate, got %+v", ce)
		}
		if ce := newEgressBypassCounterexample(iso, sink, nil); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with transitive-egress path type", func(t *testing.T) {
		ce := newEgressBypassCounterexample(iso, sink, match)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.PathType != "transitive-egress" {
			t.Errorf("PathType = %q, want transitive-egress", ce.PathType)
		}
		if ce.Source != "i-iso" || ce.Destination != "i-sink" || ce.Port != 443 {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})
}

func Test_newEgressGatedCounterexample(t *testing.T) {
	iso := &Host{ID: "i-iso"}
	gated := egressCandidate{
		host:   &Host{ID: "i-gated"},
		route:  Route{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-01"},
		target: RouteTarget{Class: routeGated, Reason: "TGW route table not resolved", TargetID: "tgw-01"},
	}
	match := &RuleMatch{SecurityGroupID: "sg-gated", RuleSource: "sg-iso", Port: 80}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newEgressGatedCounterexample(nil, gated, match); ce != nil {
			t.Errorf("expected nil for nil iso, got %+v", ce)
		}
		if ce := newEgressGatedCounterexample(iso, egressCandidate{}, match); ce != nil {
			t.Errorf("expected nil for empty candidate, got %+v", ce)
		}
		if ce := newEgressGatedCounterexample(iso, gated, nil); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with gated-egress path type", func(t *testing.T) {
		ce := newEgressGatedCounterexample(iso, gated, match)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.PathType != "gated-egress" {
			t.Errorf("PathType = %q, want gated-egress", ce.PathType)
		}
		if ce.Source != "i-iso" || ce.Destination != "i-gated" || ce.Port != 80 {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})
}

func TestNewGraph(t *testing.T) {
	g := NewGraph()
	if g == nil {
		t.Fatal("expected non-nil Graph")
	}
	if g.Hosts == nil {
		t.Error("Hosts map should be initialized")
	}
	if g.SGRules == nil {
		t.Error("SGRules map should be initialized")
	}
	if g.Subnets == nil {
		t.Error("Subnets map should be initialized")
	}
	if g.Routes == nil {
		t.Error("Routes map should be initialized")
	}
	if g.Firewalls == nil {
		t.Error("Firewalls map should be initialized")
	}
}

func TestGraph_findRelayTransitiveSSHBypass(t *testing.T) {
	prodHost := &Host{ID: "i-prod", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}}
	relayHost := &Host{ID: "i-relay", SGIDs: []string{"sg-relay"}, Tags: map[string]string{"stave:environment": "development"}}
	internalHost := &Host{ID: "i-internal", SGIDs: []string{"sg-internal"}, Tags: map[string]string{"stave:environment": "development"}}
	relayMatch := newRuleMatch("sg-prod", "sg:sg-relay", "sg-ref", 22)

	t.Run("handles nil receiver or arguments gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if ce, reason := nilGraph.findRelayTransitiveSSHBypass(relayHost, prodHost, 22, relayMatch); ce != nil || reason != "" {
			t.Errorf("expected nil for nil graph, got %+v, %q", ce, reason)
		}
		g := NewGraph()
		if ce, reason := g.findRelayTransitiveSSHBypass(nil, prodHost, 22, relayMatch); ce != nil || reason != "" {
			t.Errorf("expected nil for nil relay, got %+v, %q", ce, reason)
		}
		if ce, reason := g.findRelayTransitiveSSHBypass(relayHost, nil, 22, relayMatch); ce != nil || reason != "" {
			t.Errorf("expected nil for nil dst, got %+v, %q", ce, reason)
		}
		if ce, reason := g.findRelayTransitiveSSHBypass(relayHost, prodHost, 22, nil); ce != nil || reason != "" {
			t.Errorf("expected nil for nil relayMatch, got %+v, %q", ce, reason)
		}
	})

	t.Run("returns nil when relay has no ingress bypasses", func(t *testing.T) {
		g := &Graph{
			Hosts:   map[string]*Host{"i-prod": prodHost, "i-relay": relayHost},
			SGRules: map[string][]SGRule{"sg-prod": {}, "sg-relay": {}},
		}
		if ce, reason := g.findRelayTransitiveSSHBypass(relayHost, prodHost, 22, relayMatch); ce != nil || reason != "" {
			t.Errorf("expected nil when no bypasses, got %+v, %q", ce, reason)
		}
	})

	t.Run("finds internet ingress bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost},
			SGRules: map[string][]SGRule{
				"sg-relay": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
				},
			},
		}
		ce, reason := g.findRelayTransitiveSSHBypass(relayHost, prodHost, 22, relayMatch)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if reason != "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})

	t.Run("finds internal host ingress bypass", func(t *testing.T) {
		g := &Graph{
			Hosts: map[string]*Host{"i-prod": prodHost, "i-relay": relayHost, "i-internal": internalHost},
			SGRules: map[string][]SGRule{
				"sg-relay": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-internal"},
				},
			},
		}
		ce, reason := g.findRelayTransitiveSSHBypass(relayHost, prodHost, 22, relayMatch)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if reason != "Transitive SSH path exists — a non-bastion host can relay SSH to production via an intermediate host." {
			t.Errorf("unexpected reason: %q", reason)
		}
	})
}

func Test_formatPrefixed(t *testing.T) {
	tests := []struct {
		prefix string
		value  string
		want   string
	}{
		{"", "", ""},
		{"nat", "", "nat"},
		{"", "10.0.0.0/8", "10.0.0.0/8"},
		{"sg", "sg-12345", "sg:sg-12345"},
		{"nat", "nat-01", "nat:nat-01"},
		{"cidr", "0.0.0.0/0", "cidr:0.0.0.0/0"},
	}

	for _, tc := range tests {
		if got := formatPrefixed(tc.prefix, tc.value); got != tc.want {
			t.Errorf("formatPrefixed(%q, %q) = %q, want %q", tc.prefix, tc.value, got, tc.want)
		}
	}
}

func TestHost_CanOriginateInternalSSHTo(t *testing.T) {
	dst := &Host{ID: "i-dst", Tags: map[string]string{"stave:environment": "production"}}
	prodSrc := &Host{ID: "i-prod-src", Tags: map[string]string{"stave:environment": "production"}}
	devSrc := &Host{ID: "i-dev-src", Tags: map[string]string{"stave:environment": "development"}}
	sameSrc := &Host{ID: "i-dst", Tags: map[string]string{"stave:environment": "development"}}

	tests := []struct {
		name string
		src  *Host
		dst  *Host
		want bool
	}{
		{"nil receiver", nil, dst, false},
		{"nil dst with dev src", devSrc, nil, true},
		{"same host", sameSrc, dst, false},
		{"production source", prodSrc, dst, false},
		{"development source to production destination", devSrc, dst, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.src.CanOriginateInternalSSHTo(tc.dst); got != tc.want {
				t.Errorf("CanOriginateInternalSSHTo() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSGRule_MatchesPort(t *testing.T) {
	rule := SGRule{Port: 22}

	if !rule.MatchesPort(22) {
		t.Error("expected rule with port 22 to match 22")
	}
	if rule.MatchesPort(80) {
		t.Error("expected rule with port 22 not to match 80")
	}
	if rule.MatchesPort(0) {
		t.Error("expected rule with port 22 not to match 0")
	}
}

func Test_newSSHPath(t *testing.T) {
	p := newSSHPath("i-src", "i-dst", 22, "sg-ref", "sg-12345", "sg:sg-client")
	if p.Source != "i-src" {
		t.Errorf("Source = %q, want i-src", p.Source)
	}
	if p.Destination != "i-dst" {
		t.Errorf("Destination = %q, want i-dst", p.Destination)
	}
	if p.Port != 22 {
		t.Errorf("Port = %d, want 22", p.Port)
	}
	if p.PathType != "sg-ref" {
		t.Errorf("PathType = %q, want sg-ref", p.PathType)
	}
	if p.RuleSG != "sg-12345" {
		t.Errorf("RuleSG = %q, want sg-12345", p.RuleSG)
	}
	if p.RuleSource != "sg:sg-client" {
		t.Errorf("RuleSource = %q, want sg:sg-client", p.RuleSource)
	}
}

func TestGraph_findSubnetBypassingRoute(t *testing.T) {
	sub := &Subnet{
		ID:           "subnet-priv-1",
		VPCID:        "vpc-1",
		RouteTableID: "rt-1",
		Tags:         map[string]string{"stave:subnet-type": "private"},
	}

	t.Run("handles nil receiver or nil subnet gracefully", func(t *testing.T) {
		var nilGraph *Graph
		if _, ok := nilGraph.findSubnetBypassingRoute(sub); ok {
			t.Error("expected false for nil graph")
		}
		g := NewGraph()
		if _, ok := g.findSubnetBypassingRoute(nil); ok {
			t.Error("expected false for nil subnet")
		}
	})

	t.Run("returns false when default route routes through firewall", func(t *testing.T) {
		g := &Graph{
			Subnets: map[string]*Subnet{"subnet-priv-1": sub},
			Routes: map[string][]Route{
				"rt-1": {
					{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-fw"},
				},
			},
			Firewalls: map[string]bool{"igw-fw": true},
		}
		if _, ok := g.findSubnetBypassingRoute(sub); ok {
			t.Error("expected false when firewall protects default route")
		}
	})

	t.Run("returns bypassing route when default route targets IGW without firewall", func(t *testing.T) {
		bypassRoute := Route{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-bypass"}
		g := &Graph{
			Subnets: map[string]*Subnet{"subnet-priv-1": sub},
			Routes: map[string][]Route{
				"rt-1": {bypassRoute},
			},
			Firewalls: map[string]bool{"igw-fw": true},
		}
		route, ok := g.findSubnetBypassingRoute(sub)
		if !ok {
			t.Fatal("expected true when default route bypasses firewall")
		}
		if route.TargetID != "igw-bypass" {
			t.Errorf("TargetID = %q, want igw-bypass", route.TargetID)
		}
	})
}

func TestHost_SafeID(t *testing.T) {
	t.Run("returns empty string for nil host", func(t *testing.T) {
		var nilHost *Host
		if id := nilHost.SafeID(); id != "" {
			t.Errorf("nilHost.SafeID() = %q, want empty string", id)
		}
	})

	t.Run("returns ID for non-nil host", func(t *testing.T) {
		h := &Host{ID: "i-0987654321"}
		if id := h.SafeID(); id != "i-0987654321" {
			t.Errorf("h.SafeID() = %q, want i-0987654321", id)
		}
	})
}

func Test_hostIdentity(t *testing.T) {
	t.Run("returns empty strings for nil host", func(t *testing.T) {
		id, vpc := hostIdentity(nil)
		if id != "" || vpc != "" {
			t.Errorf("hostIdentity(nil) = (%q, %q), want empty strings", id, vpc)
		}
	})

	t.Run("returns ID and VPCID for non-nil host", func(t *testing.T) {
		h := &Host{ID: "i-012345", VPCID: "vpc-abcdef"}
		id, vpc := hostIdentity(h)
		if id != "i-012345" {
			t.Errorf("id = %q, want i-012345", id)
		}
		if vpc != "vpc-abcdef" {
			t.Errorf("vpc = %q, want vpc-abcdef", vpc)
		}
	})
}

func TestGraph_findCrossVPCDatabaseBypass(t *testing.T) {
	t.Run("handles nil receiver or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		dst := &Host{ID: "db-1", VPCID: "vpc-db"}
		if ce, reason := nilGraph.findCrossVPCDatabaseBypass(dst); ce != nil || reason != "" {
			t.Error("expected nil for nil graph")
		}
		g := NewGraph()
		if ce, reason := g.findCrossVPCDatabaseBypass(nil); ce != nil || reason != "" {
			t.Error("expected nil for nil dst")
		}
	})

	t.Run("detects cross-vpc bypass", func(t *testing.T) {
		g := BuildGraph([]asset.Snapshot{databaseExposedSnapshot()})
		dbHosts := g.DatabaseHosts()
		if len(dbHosts) == 0 {
			t.Fatal("expected database hosts")
		}
		ce, reason := g.findCrossVPCDatabaseBypass(dbHosts[0])
		if ce == nil {
			t.Fatal("expected cross-vpc counterexample")
		}
		if ce.PathType != "cross-vpc" {
			t.Errorf("PathType = %q, want cross-vpc", ce.PathType)
		}
		if reason == "" {
			t.Error("expected non-empty reason")
		}
	})
}

func TestGraph_findCrossVPCHostBypass(t *testing.T) {
	t.Run("handles nil receiver, nil src, or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		src := &Host{ID: "src-1", VPCID: "vpc-app"}
		dst := &Host{ID: "db-1", VPCID: "vpc-db"}
		if ce, reason := nilGraph.findCrossVPCHostBypass(src, dst); ce != nil || reason != "" {
			t.Error("expected nil for nil graph")
		}
		g := NewGraph()
		if ce, reason := g.findCrossVPCHostBypass(nil, dst); ce != nil || reason != "" {
			t.Error("expected nil for nil src")
		}
		if ce, reason := g.findCrossVPCHostBypass(src, nil); ce != nil || reason != "" {
			t.Error("expected nil for nil dst")
		}
	})

	t.Run("returns nil when src is internal to dst", func(t *testing.T) {
		g := NewGraph()
		src := &Host{ID: "db-replica", VPCID: "vpc-db"}
		dst := &Host{ID: "db-primary", VPCID: "vpc-db"}
		if ce, reason := g.findCrossVPCHostBypass(src, dst); ce != nil || reason != "" {
			t.Errorf("expected nil for internal hosts, got ce=%v, reason=%q", ce, reason)
		}
	})

	t.Run("detects cross-vpc reachability to database host", func(t *testing.T) {
		g := BuildGraph([]asset.Snapshot{databaseExposedSnapshot()})
		dbHosts := g.DatabaseHosts()
		if len(dbHosts) == 0 {
			t.Fatal("expected database hosts")
		}
		dst := dbHosts[0]
		var found bool
		for _, src := range g.allHosts() {
			if ce, reason := g.findCrossVPCHostBypass(src, dst); ce != nil {
				found = true
				if ce.PathType != "cross-vpc" {
					t.Errorf("PathType = %q, want cross-vpc", ce.PathType)
				}
				if ce.Destination != dst.ID {
					t.Errorf("Destination = %q, want %q", ce.Destination, dst.ID)
				}
				if reason == "" {
					t.Error("expected non-empty reason")
				}
				break
			}
		}
		if !found {
			t.Fatal("expected to find cross-vpc host bypass in exposed snapshot")
		}
	})

	t.Run("returns nil when no reachability exists between cross-vpc hosts", func(t *testing.T) {
		g := NewGraph()
		src := &Host{ID: "app-1", VPCID: "vpc-app", SGIDs: []string{"sg-app"}}
		dst := &Host{ID: "db-1", VPCID: "vpc-db", SGIDs: []string{"sg-db"}}
		g.Hosts[src.ID] = src
		g.Hosts[dst.ID] = dst
		// No security group rules permitting access
		if ce, reason := g.findCrossVPCHostBypass(src, dst); ce != nil || reason != "" {
			t.Errorf("expected nil when no reachability exists, got ce=%v, reason=%q", ce, reason)
		}
	})
}

func TestGraph_findInternetDatabaseBypass(t *testing.T) {
	t.Run("handles nil receiver or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		dst := &Host{ID: "db-1", VPCID: "vpc-db"}
		if ce, reason := nilGraph.findInternetDatabaseBypass(dst); ce != nil || reason != "" {
			t.Error("expected nil for nil graph")
		}
		g := NewGraph()
		if ce, reason := g.findInternetDatabaseBypass(nil); ce != nil || reason != "" {
			t.Error("expected nil for nil dst")
		}
	})

	t.Run("detects internet bypass", func(t *testing.T) {
		g := BuildGraph([]asset.Snapshot{databaseExternalIngressSnapshot()})
		dbHosts := g.DatabaseHosts()
		if len(dbHosts) == 0 {
			t.Fatal("expected database hosts")
		}
		ce, reason := g.findInternetDatabaseBypass(dbHosts[0])
		if ce == nil {
			t.Fatal("expected internet ingress counterexample")
		}
		if ce.PathType != "external" {
			t.Errorf("PathType = %q, want external", ce.PathType)
		}
		if reason == "" {
			t.Error("expected non-empty reason")
		}
	})
}

func Test_newCrossVPCDatabaseBypassCounterexample(t *testing.T) {
	src := &Host{ID: "i-app", VPCID: "vpc-app"}
	dst := &Host{ID: "i-db", VPCID: "vpc-db"}
	match := &RuleMatch{SecurityGroupID: "sg-db", RuleSource: "10.0.0.0/8", PathType: "cross-vpc", Port: 5432}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newCrossVPCDatabaseBypassCounterexample(nil, dst, match); ce != nil {
			t.Errorf("expected nil for nil src, got %+v", ce)
		}
		if ce := newCrossVPCDatabaseBypassCounterexample(src, nil, match); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newCrossVPCDatabaseBypassCounterexample(src, dst, nil); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with source, destination, and remediation", func(t *testing.T) {
		ce := newCrossVPCDatabaseBypassCounterexample(src, dst, match)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-app" || ce.Destination != "i-db" || ce.Port != 5432 || ce.PathType != "cross-vpc" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
		if !strings.Contains(ce.Explanation, "Host i-app (vpc:vpc-app) can reach database host i-db (vpc:vpc-db) via cross-vpc.") {
			t.Errorf("unexpected explanation: %q", ce.Explanation)
		}
		if !strings.Contains(ce.Remediation, "Remove cross-VPC ingress to database SG sg-db.") {
			t.Errorf("unexpected remediation: %q", ce.Remediation)
		}
	})
}

func Test_newInternetDatabaseBypassCounterexample(t *testing.T) {
	dst := &Host{ID: "i-db", VPCID: "vpc-db"}
	match := &RuleMatch{SecurityGroupID: "sg-db", RuleSource: "0.0.0.0/0", PathType: "external", Port: 5432}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newInternetDatabaseBypassCounterexample(nil, match); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newInternetDatabaseBypassCounterexample(dst, nil); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with source, destination, and remediation", func(t *testing.T) {
		ce := newInternetDatabaseBypassCounterexample(dst, match)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "0.0.0.0/0 (internet)" || ce.Destination != "i-db" || ce.Port != 5432 || ce.PathType != "external" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
		if !strings.Contains(ce.Explanation, "Database host i-db accepts traffic from 0.0.0.0/0 on port 5432 via sg-db.") {
			t.Errorf("unexpected explanation: %q", ce.Explanation)
		}
		if !strings.Contains(ce.Remediation, "Remove internet ingress on sg-db. Database hosts must not be reachable from the internet.") {
			t.Errorf("unexpected remediation: %q", ce.Remediation)
		}
	})
}

func Test_newEgressCandidate(t *testing.T) {
	h := &Host{ID: "i-egress"}
	route := Route{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"}
	target := RouteTarget{Class: routeSink, TargetID: "nat-01"}

	c := newEgressCandidate(h, route, target)
	if c.host != h {
		t.Errorf("c.host = %v, want %v", c.host, h)
	}
	if c.route != route {
		t.Errorf("c.route = %+v, want %+v", c.route, route)
	}
	if c.target != target {
		t.Errorf("c.target = %+v, want %+v", c.target, target)
	}
	if c.RouteDestination() != "0.0.0.0/0" {
		t.Errorf("c.RouteDestination() = %q, want 0.0.0.0/0", c.RouteDestination())
	}
	if c.RouteTarget() != "nat:nat-01" {
		t.Errorf("c.RouteTarget() = %q, want nat:nat-01", c.RouteTarget())
	}
	if c.RouteTargetType() != "nat" {
		t.Errorf("c.RouteTargetType() = %q, want nat", c.RouteTargetType())
	}
	if c.TargetID() != "nat-01" {
		t.Errorf("c.TargetID() = %q, want nat-01", c.TargetID())
	}
	if c.TargetReason() != "" {
		t.Errorf("c.TargetReason() = %q, want empty string", c.TargetReason())
	}
}

func TestGraph_hostEgressCandidate(t *testing.T) {
	t.Run("handles nil receiver or nil host gracefully", func(t *testing.T) {
		var nilGraph *Graph
		h := &Host{ID: "h-1", SubnetID: "sub-1"}
		if _, ok := nilGraph.hostEgressCandidate(h); ok {
			t.Error("expected false for nil graph")
		}
		g := NewGraph()
		if _, ok := g.hostEgressCandidate(nil); ok {
			t.Error("expected false for nil host")
		}
	})

	t.Run("returns false for isolated host", func(t *testing.T) {
		g := NewGraph()
		h := &Host{ID: "h-iso", Tags: map[string]string{"stave:network-zone": "isolated"}}
		if _, ok := g.hostEgressCandidate(h); ok {
			t.Error("expected false for isolated host")
		}
	})

	t.Run("returns false when host has no route table", func(t *testing.T) {
		g := NewGraph()
		h := &Host{ID: "h-noroute", SubnetID: "sub-noroute"}
		g.Hosts[h.ID] = h
		g.Subnets["sub-noroute"] = &Subnet{ID: "sub-noroute"}
		if _, ok := g.hostEgressCandidate(h); ok {
			t.Error("expected false for host without route table")
		}
	})

	t.Run("returns false when host only has local default route", func(t *testing.T) {
		g := NewGraph()
		h := &Host{ID: "h-local", SubnetID: "sub-local"}
		g.Hosts[h.ID] = h
		g.Subnets["sub-local"] = &Subnet{ID: "sub-local", RouteTableID: "rt-local"}
		g.Routes["rt-local"] = []Route{
			{Destination: "0.0.0.0/0", TargetType: "local", TargetID: "local"},
		}
		if _, ok := g.hostEgressCandidate(h); ok {
			t.Error("expected false for local-only route target")
		}
	})

	t.Run("returns sink candidate when host has NAT default route", func(t *testing.T) {
		g := NewGraph()
		h := &Host{ID: "h-nat", SubnetID: "sub-nat"}
		g.Hosts[h.ID] = h
		g.Subnets["sub-nat"] = &Subnet{ID: "sub-nat", RouteTableID: "rt-nat"}
		g.Routes["rt-nat"] = []Route{
			{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-01"},
		}
		c, ok := g.hostEgressCandidate(h)
		if !ok {
			t.Fatal("expected true for host with NAT default route")
		}
		if !c.target.IsSink() {
			t.Error("expected candidate target to be a sink")
		}
		if c.host.ID != "h-nat" {
			t.Errorf("host.ID = %q, want h-nat", c.host.ID)
		}
	})

	t.Run("returns gated candidate when host has TGW default route", func(t *testing.T) {
		g := NewGraph()
		h := &Host{ID: "h-tgw", SubnetID: "sub-tgw"}
		g.Hosts[h.ID] = h
		g.Subnets["sub-tgw"] = &Subnet{ID: "sub-tgw", RouteTableID: "rt-tgw"}
		g.Routes["rt-tgw"] = []Route{
			{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-01"},
		}
		c, ok := g.hostEgressCandidate(h)
		if !ok {
			t.Fatal("expected true for host with TGW default route")
		}
		if !c.target.IsGated() {
			t.Error("expected candidate target to be gated")
		}
	})
}

func TestGraph_enumerateHostSSHPaths(t *testing.T) {
	t.Run("handles nil receiver or nil dst gracefully", func(t *testing.T) {
		var nilGraph *Graph
		dst := &Host{ID: "i-dst"}
		if paths := nilGraph.enumerateHostSSHPaths(dst, 22); paths != nil {
			t.Errorf("enumerateHostSSHPaths on nil graph = %v, want nil", paths)
		}
		g := NewGraph()
		if paths := g.enumerateHostSSHPaths(nil, 22); paths != nil {
			t.Errorf("enumerateHostSSHPaths with nil dst = %v, want nil", paths)
		}
	})

	t.Run("enumerates paths for host in bypassed snapshot", func(t *testing.T) {
		g := BuildGraph([]asset.Snapshot{bastionBypassedSnapshot()})
		prodHosts := g.ProductionHosts()
		if len(prodHosts) == 0 {
			t.Fatal("expected production hosts in bypassed snapshot")
		}
		paths := g.enumerateHostSSHPaths(prodHosts[0], 22)
		if len(paths) == 0 {
			t.Fatal("expected at least one SSH path for bypassed production host")
		}
	})

	t.Run("returns empty slice when host has no paths", func(t *testing.T) {
		g := NewGraph()
		h := &Host{ID: "i-isolated", VPCID: "vpc-1"}
		g.Hosts[h.ID] = h
		paths := g.enumerateHostSSHPaths(h, 22)
		if len(paths) != 0 {
			t.Errorf("enumerateHostSSHPaths = %v, want empty", paths)
		}
	})
}

func TestGraph_findInternalSSHPath(t *testing.T) {
	t.Run("handles nil receiver or nil hosts gracefully", func(t *testing.T) {
		var nilGraph *Graph
		src := &Host{ID: "i-src"}
		dst := &Host{ID: "i-dst"}
		if _, ok := nilGraph.findInternalSSHPath(src, dst, 22); ok {
			t.Error("expected false for nil graph")
		}
		g := NewGraph()
		if _, ok := g.findInternalSSHPath(nil, dst, 22); ok {
			t.Error("expected false for nil src")
		}
		if _, ok := g.findInternalSSHPath(src, nil, 22); ok {
			t.Error("expected false for nil dst")
		}
	})

	t.Run("returns false when src cannot originate to dst", func(t *testing.T) {
		g := NewGraph()
		src := &Host{ID: "i-prod1", Tags: map[string]string{"stave:environment": "production"}}
		dst := &Host{ID: "i-prod2", Tags: map[string]string{"stave:environment": "production"}}
		if _, ok := g.findInternalSSHPath(src, dst, 22); ok {
			t.Error("expected false when src cannot originate to dst")
		}
	})

	t.Run("returns authorized path when reachability exists", func(t *testing.T) {
		src := &Host{ID: "i-dev", VPCID: "vpc-1", SGIDs: []string{"sg-dev"}, Tags: map[string]string{"stave:environment": "development"}}
		dst := &Host{ID: "i-prod", VPCID: "vpc-1", SGIDs: []string{"sg-prod"}, Tags: map[string]string{"stave:environment": "production"}}
		g := &Graph{
			Hosts: map[string]*Host{"i-dev": src, "i-prod": dst},
			SGRules: map[string][]SGRule{
				"sg-prod": {
					{Direction: "ingress", Protocol: "tcp", Port: 22, SourceType: "sg", SourceValue: "sg-dev"},
				},
			},
		}
		path, ok := g.findInternalSSHPath(src, dst, 22)
		if !ok {
			t.Fatal("expected authorized internal SSH path")
		}
		if path.Source != "i-dev" || path.Destination != "i-prod" {
			t.Errorf("path = %+v, want source i-dev, dest i-prod", path)
		}
		if path.Port != 22 {
			t.Errorf("path.Port = %d, want 22", path.Port)
		}
	})
}

func TestGraph_findExternalSSHPath(t *testing.T) {
	t.Run("handles nil receiver, nil dst, or nil match gracefully", func(t *testing.T) {
		var nilGraph *Graph
		dst := &Host{ID: "i-dst"}
		match := newRuleMatch("sg-1", "0.0.0.0/0", "external", 22)
		if _, ok := nilGraph.findExternalSSHPath(dst, match); ok {
			t.Error("expected false for nil graph")
		}
		g := NewGraph()
		if _, ok := g.findExternalSSHPath(nil, match); ok {
			t.Error("expected false for nil dst")
		}
		if _, ok := g.findExternalSSHPath(dst, nil); ok {
			t.Error("expected false for nil match")
		}
	})

	t.Run("converts rule match into external SSHPath", func(t *testing.T) {
		g := NewGraph()
		dst := &Host{ID: "i-prod-01"}
		match := newRuleMatch("sg-prod", "0.0.0.0/0", "external", 22)
		path, ok := g.findExternalSSHPath(dst, match)
		if !ok {
			t.Fatal("expected ok = true")
		}
		if path.Source != "0.0.0.0/0" {
			t.Errorf("Source = %q, want 0.0.0.0/0", path.Source)
		}
		if path.Destination != "i-prod-01" {
			t.Errorf("Destination = %q, want i-prod-01", path.Destination)
		}
		if path.Port != 22 {
			t.Errorf("Port = %d, want 22", path.Port)
		}
		if path.PathType != "external" {
			t.Errorf("PathType = %q, want external", path.PathType)
		}
	})
}

func Test_egressCandidatePartition(t *testing.T) {
	t.Run("zero value partition IsEmpty reports true", func(t *testing.T) {
		var p egressCandidatePartition
		if !p.IsEmpty() {
			t.Error("expected IsEmpty() == true for zero value partition")
		}
	})

	t.Run("partition with sinks only IsEmpty reports false", func(t *testing.T) {
		p := egressCandidatePartition{
			sinks: []egressCandidate{{host: &Host{ID: "i-sink"}}},
		}
		if p.IsEmpty() {
			t.Error("expected IsEmpty() == false when sinks exist")
		}
	})

	t.Run("partition with gated only IsEmpty reports false", func(t *testing.T) {
		p := egressCandidatePartition{
			gated: []egressCandidate{{host: &Host{ID: "i-gated"}}},
		}
		if p.IsEmpty() {
			t.Error("expected IsEmpty() == false when gated candidates exist")
		}
	})

	t.Run("partition with both sinks and gated IsEmpty reports false", func(t *testing.T) {
		p := egressCandidatePartition{
			sinks: []egressCandidate{{host: &Host{ID: "i-sink"}}},
			gated: []egressCandidate{{host: &Host{ID: "i-gated"}}},
		}
		if p.IsEmpty() {
			t.Error("expected IsEmpty() == false when sinks and gated candidates exist")
		}
	})

	t.Run("nil graph findEgressCandidates returns empty partition", func(t *testing.T) {
		var nilGraph *Graph
		p := nilGraph.findEgressCandidates()
		if !p.IsEmpty() {
			t.Errorf("expected empty partition for nil graph, got %+v", p)
		}
	})

	t.Run("populates sinks and gated according to route target classification", func(t *testing.T) {
		g := NewGraph()
		// Host 1: default route to igw (sink)
		g.Hosts["i-sink"] = &Host{ID: "i-sink", SubnetID: "sub-igw"}
		g.Subnets["sub-igw"] = &Subnet{ID: "sub-igw", RouteTableID: "rtb-igw"}
		g.Routes["rtb-igw"] = []Route{
			{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-1"},
		}

		// Host 2: default route to tgw (gated)
		g.Hosts["i-gated"] = &Host{ID: "i-gated", SubnetID: "sub-tgw"}
		g.Subnets["sub-tgw"] = &Subnet{ID: "sub-tgw", RouteTableID: "rtb-tgw"}
		g.Routes["rtb-tgw"] = []Route{
			{Destination: "0.0.0.0/0", TargetType: "tgw", TargetID: "tgw-1"},
		}

		// Host 3: isolated host (should be skipped)
		g.Hosts["i-iso"] = &Host{
			ID:       "i-iso",
			SubnetID: "sub-igw",
			Tags:     map[string]string{"stave:network-zone": "isolated"},
		}

		p := g.findEgressCandidates()
		if p.IsEmpty() {
			t.Fatal("expected non-empty candidate partition")
		}
		if len(p.sinks) != 1 || p.sinks[0].host.ID != "i-sink" {
			t.Errorf("expected 1 sink (i-sink), got %+v", p.sinks)
		}
		if len(p.gated) != 1 || p.gated[0].host.ID != "i-gated" {
			t.Errorf("expected 1 gated (i-gated), got %+v", p.gated)
		}
	})
}

func TestHost_Tag(t *testing.T) {
	t.Run("nil host returns empty string", func(t *testing.T) {
		var nilHost *Host
		if val := nilHost.Tag("stave:role"); val != "" {
			t.Errorf("nilHost.Tag() = %q, want empty string", val)
		}
	})

	t.Run("nil tags map returns empty string", func(t *testing.T) {
		h := &Host{ID: "i-nil-tags"}
		if val := h.Tag("stave:role"); val != "" {
			t.Errorf("h.Tag() = %q, want empty string", val)
		}
	})

	t.Run("missing key returns empty string", func(t *testing.T) {
		h := &Host{ID: "i-1", Tags: map[string]string{"env": "prod"}}
		if val := h.Tag("other"); val != "" {
			t.Errorf("h.Tag() = %q, want empty string", val)
		}
	})

	t.Run("existing tag returns value", func(t *testing.T) {
		h := &Host{ID: "i-1", Tags: map[string]string{"env": "prod"}}
		if val := h.Tag("env"); val != "prod" {
			t.Errorf("h.Tag() = %q, want prod", val)
		}
	})
}

func TestHost_TagPredicates_NilSafe(t *testing.T) {
	var nilHost *Host

	if nilHost.IsProduction() {
		t.Error("nilHost.IsProduction() should be false")
	}
	if nilHost.IsBastion() {
		t.Error("nilHost.IsBastion() should be false")
	}
	if nilHost.IsDevelopment() {
		t.Error("nilHost.IsDevelopment() should be false")
	}
	if nilHost.IsDatabaseTier() {
		t.Error("nilHost.IsDatabaseTier() should be false")
	}
	if nilHost.IsIsolated() {
		t.Error("nilHost.IsIsolated() should be false")
	}
}

func Test_newInternalBastionBypassCounterexample(t *testing.T) {
	src := &Host{ID: "i-src"}
	dst := &Host{ID: "i-dst"}
	match := &RuleMatch{SecurityGroupID: "sg-prod", RuleSource: "10.0.0.0/16", PathType: "vpc-peering", Port: 22}
	bastions := []*Host{{ID: "i-bastion"}}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newInternalBastionBypassCounterexample(nil, dst, 22, match, bastions); ce != nil {
			t.Errorf("expected nil for nil src, got %+v", ce)
		}
		if ce := newInternalBastionBypassCounterexample(src, nil, 22, match, bastions); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newInternalBastionBypassCounterexample(src, dst, 22, nil, bastions); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with correct fields", func(t *testing.T) {
		ce := newInternalBastionBypassCounterexample(src, dst, 22, match, bastions)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-src" || ce.Destination != "i-dst" || ce.Port != 22 || ce.PathType != "vpc-peering" {
			t.Errorf("unexpected counterexample fields: %+v", ce)
		}
		if ce.RuleSG != "sg-prod" || ce.RuleSource != "10.0.0.0/16" {
			t.Errorf("unexpected rule fields: %+v", ce)
		}
	})
}

func Test_newExternalBypassCounterexample(t *testing.T) {
	dst := &Host{ID: "i-dst"}
	match := &RuleMatch{SecurityGroupID: "sg-prod", RuleSource: "0.0.0.0/0", PathType: "external", Port: 22}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newExternalBypassCounterexample(nil, 22, match); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newExternalBypassCounterexample(dst, 22, nil); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
	})

	t.Run("formats counterexample with internet label and correct fields", func(t *testing.T) {
		ce := newExternalBypassCounterexample(dst, 22, match)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "0.0.0.0/0 (internet)" || ce.Destination != "i-dst" || ce.Port != 22 || ce.PathType != "external" {
			t.Errorf("unexpected counterexample fields: %+v", ce)
		}
		if ce.RuleSG != "sg-prod" || ce.RuleSource != "0.0.0.0/0" {
			t.Errorf("unexpected rule fields: %+v", ce)
		}
	})
}

func TestSubnet_SafeID(t *testing.T) {
	t.Run("returns empty string for nil subnet", func(t *testing.T) {
		var nilSubnet *Subnet
		if id := nilSubnet.SafeID(); id != "" {
			t.Errorf("nilSubnet.SafeID() = %q, want empty string", id)
		}
	})

	t.Run("returns ID for non-nil subnet", func(t *testing.T) {
		s := &Subnet{ID: "subnet-12345"}
		if id := s.SafeID(); id != "subnet-12345" {
			t.Errorf("s.SafeID() = %q, want subnet-12345", id)
		}
	})
}

func TestSubnet_Tag(t *testing.T) {
	t.Run("nil subnet returns empty string", func(t *testing.T) {
		var nilSubnet *Subnet
		if val := nilSubnet.Tag("stave:subnet-type"); val != "" {
			t.Errorf("nilSubnet.Tag() = %q, want empty string", val)
		}
	})

	t.Run("nil tags map returns empty string", func(t *testing.T) {
		s := &Subnet{ID: "subnet-1"}
		if val := s.Tag("stave:subnet-type"); val != "" {
			t.Errorf("s.Tag() = %q, want empty string", val)
		}
	})

	t.Run("missing key returns empty string", func(t *testing.T) {
		s := &Subnet{ID: "subnet-1", Tags: map[string]string{"env": "prod"}}
		if val := s.Tag("stave:subnet-type"); val != "" {
			t.Errorf("s.Tag() = %q, want empty string", val)
		}
	})

	t.Run("existing tag returns value", func(t *testing.T) {
		s := &Subnet{ID: "subnet-1", Tags: map[string]string{"stave:subnet-type": "private"}}
		if val := s.Tag("stave:subnet-type"); val != "private" {
			t.Errorf("s.Tag() = %q, want private", val)
		}
	})
}

func TestSubnet_IsPrivate(t *testing.T) {
	t.Run("nil subnet returns false", func(t *testing.T) {
		var nilSubnet *Subnet
		if nilSubnet.IsPrivate() {
			t.Error("nilSubnet.IsPrivate() should be false")
		}
	})

	t.Run("subnet tagged private returns true", func(t *testing.T) {
		s := &Subnet{Tags: map[string]string{"stave:subnet-type": "private"}}
		if !s.IsPrivate() {
			t.Error("s.IsPrivate() should be true")
		}
	})

	t.Run("subnet tagged public returns false", func(t *testing.T) {
		s := &Subnet{Tags: map[string]string{"stave:subnet-type": "public"}}
		if s.IsPrivate() {
			t.Error("s.IsPrivate() should be false")
		}
	})

	t.Run("untagged subnet returns false", func(t *testing.T) {
		s := &Subnet{}
		if s.IsPrivate() {
			t.Error("s.IsPrivate() should be false")
		}
	})
}

func Test_newTransitiveInternetBypassCounterexample(t *testing.T) {
	relay := &Host{ID: "i-relay"}
	dst := &Host{ID: "i-prod"}
	match := &RuleMatch{RuleSource: "0.0.0.0/0"}
	relayMatch := &RuleMatch{SecurityGroupID: "sg-prod", RuleSource: "sg:sg-relay", PathType: "sg-ref", Port: 22}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newTransitiveInternetBypassCounterexample(nil, dst, 22, match, relayMatch); ce != nil {
			t.Errorf("expected nil for nil relay, got %+v", ce)
		}
		if ce := newTransitiveInternetBypassCounterexample(relay, nil, 22, match, relayMatch); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newTransitiveInternetBypassCounterexample(relay, dst, 22, nil, relayMatch); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
		if ce := newTransitiveInternetBypassCounterexample(relay, dst, 22, match, nil); ce != nil {
			t.Errorf("expected nil for nil relayMatch, got %+v", ce)
		}
	})

	t.Run("formats counterexample with two-hop internet path", func(t *testing.T) {
		ce := newTransitiveInternetBypassCounterexample(relay, dst, 22, match, relayMatch)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "0.0.0.0/0 -> i-relay" || ce.Destination != "i-prod" || ce.PathType != "transitive" || ce.Port != 22 {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
		if !strings.Contains(ce.Explanation, "Host i-relay is SSH-accessible from the internet and can reach production host i-prod") {
			t.Errorf("unexpected explanation: %q", ce.Explanation)
		}
		if !strings.Contains(ce.Remediation, "Remove SSH ingress from 0.0.0.0/0 on i-relay or remove its access to production host i-prod.") {
			t.Errorf("unexpected remediation: %q", ce.Remediation)
		}
	})
}

func Test_newTransitiveInternalBypassCounterexample(t *testing.T) {
	src := &Host{ID: "i-src"}
	relay := &Host{ID: "i-relay"}
	dst := &Host{ID: "i-prod"}
	match := &RuleMatch{SecurityGroupID: "sg-relay", RuleSource: "10.0.0.0/16", PathType: "vpc-peering", Port: 22}
	relayMatch := &RuleMatch{SecurityGroupID: "sg-prod", RuleSource: "sg:sg-relay", PathType: "sg-ref", Port: 22}

	t.Run("returns nil on nil arguments", func(t *testing.T) {
		if ce := newTransitiveInternalBypassCounterexample(nil, relay, dst, 22, match, relayMatch); ce != nil {
			t.Errorf("expected nil for nil src, got %+v", ce)
		}
		if ce := newTransitiveInternalBypassCounterexample(src, nil, dst, 22, match, relayMatch); ce != nil {
			t.Errorf("expected nil for nil relay, got %+v", ce)
		}
		if ce := newTransitiveInternalBypassCounterexample(src, relay, nil, 22, match, relayMatch); ce != nil {
			t.Errorf("expected nil for nil dst, got %+v", ce)
		}
		if ce := newTransitiveInternalBypassCounterexample(src, relay, dst, 22, nil, relayMatch); ce != nil {
			t.Errorf("expected nil for nil match, got %+v", ce)
		}
		if ce := newTransitiveInternalBypassCounterexample(src, relay, dst, 22, match, nil); ce != nil {
			t.Errorf("expected nil for nil relayMatch, got %+v", ce)
		}
	})

	t.Run("formats counterexample with two-hop internal path", func(t *testing.T) {
		ce := newTransitiveInternalBypassCounterexample(src, relay, dst, 22, match, relayMatch)
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Source != "i-src -> i-relay" || ce.Destination != "i-prod" || ce.PathType != "transitive" || ce.Port != 22 {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
		if !strings.Contains(ce.Explanation, "Host i-src can reach i-relay, which can reach production host i-prod") {
			t.Errorf("unexpected explanation: %q", ce.Explanation)
		}
		if !strings.Contains(ce.Remediation, "Remove SSH access from i-src to i-relay or from i-relay to production host i-prod.") {
			t.Errorf("unexpected remediation: %q", ce.Remediation)
		}
	})
}

func TestSupportedProperties(t *testing.T) {
	expected := []string{
		"bastion-ssh",
		"prod-dev-isolation",
		"database-isolation",
		"firewall-mandatory",
		"transitive-ssh",
		"transitive-egress",
	}
	if len(SupportedProperties) != len(expected) {
		t.Fatalf("len(SupportedProperties) = %d, want %d", len(SupportedProperties), len(expected))
	}
	for i, p := range expected {
		if SupportedProperties[i] != p {
			t.Errorf("SupportedProperties[%d] = %q, want %q", i, SupportedProperties[i], p)
		}
	}
}

func TestGraph_HasFirewall(t *testing.T) {
	t.Run("nil graph returns false", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.HasFirewall("vpce-123") {
			t.Error("nilGraph.HasFirewall() should be false")
		}
	})

	t.Run("nil Firewalls map returns false", func(t *testing.T) {
		g := &Graph{}
		if g.HasFirewall("vpce-123") {
			t.Error("g.HasFirewall() should be false when map is nil")
		}
	})

	t.Run("empty targetID returns false", func(t *testing.T) {
		g := &Graph{Firewalls: map[string]bool{"vpce-123": true}}
		if g.HasFirewall("") {
			t.Error("g.HasFirewall(\"\") should be false")
		}
	})

	t.Run("returns true when firewall exists", func(t *testing.T) {
		g := &Graph{Firewalls: map[string]bool{"vpce-123": true}}
		if !g.HasFirewall("vpce-123") {
			t.Error("expected true for existing firewall")
		}
		if g.HasFirewall("vpce-other") {
			t.Error("expected false for missing firewall")
		}
	})
}

func TestGraph_FirewallCount(t *testing.T) {
	t.Run("nil graph returns 0", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.FirewallCount() != 0 {
			t.Errorf("nilGraph.FirewallCount() = %d, want 0", nilGraph.FirewallCount())
		}
	})

	t.Run("returns count of firewall endpoints", func(t *testing.T) {
		g := &Graph{Firewalls: map[string]bool{"vpce-1": true, "vpce-2": true}}
		if g.FirewallCount() != 2 {
			t.Errorf("g.FirewallCount() = %d, want 2", g.FirewallCount())
		}
	})
}

func TestCounterexample_IsDirectIGW(t *testing.T) {
	t.Run("nil counterexample returns false", func(t *testing.T) {
		var nilCE *Counterexample
		if nilCE.IsDirectIGW() {
			t.Error("nilCE.IsDirectIGW() should be false")
		}
	})

	t.Run("non-direct-igw path returns false", func(t *testing.T) {
		ce := &Counterexample{PathType: "ingress"}
		if ce.IsDirectIGW() {
			t.Error("expected false for ingress path type")
		}
	})

	t.Run("direct-igw path returns true", func(t *testing.T) {
		ce := &Counterexample{PathType: "direct-igw"}
		if !ce.IsDirectIGW() {
			t.Error("expected true for direct-igw path type")
		}
	})
}

func TestProofResult_Predicates(t *testing.T) {
	t.Run("nil result returns false for all predicates", func(t *testing.T) {
		var nilRes *ProofResult
		if nilRes.IsSAT() {
			t.Error("nilRes.IsSAT() should be false")
		}
		if nilRes.IsUNSAT() {
			t.Error("nilRes.IsUNSAT() should be false")
		}
		if nilRes.IsEvidenceGated() {
			t.Error("nilRes.IsEvidenceGated() should be false")
		}
	})

	t.Run("SAT result", func(t *testing.T) {
		r := &ProofResult{Result: "SAT"}
		if !r.IsSAT() {
			t.Error("expected IsSAT() to be true")
		}
		if r.IsUNSAT() {
			t.Error("expected IsUNSAT() to be false")
		}
		if r.IsEvidenceGated() {
			t.Error("expected IsEvidenceGated() to be false")
		}
	})

	t.Run("UNSAT result", func(t *testing.T) {
		r := &ProofResult{Result: "UNSAT"}
		if r.IsSAT() {
			t.Error("expected IsSAT() to be false")
		}
		if !r.IsUNSAT() {
			t.Error("expected IsUNSAT() to be true")
		}
		if r.IsEvidenceGated() {
			t.Error("expected IsEvidenceGated() to be false")
		}
	})

	t.Run("EVIDENCE_GATED result", func(t *testing.T) {
		r := &ProofResult{Result: "EVIDENCE_GATED"}
		if r.IsSAT() {
			t.Error("expected IsSAT() to be false")
		}
		if r.IsUNSAT() {
			t.Error("expected IsUNSAT() to be false")
		}
		if !r.IsEvidenceGated() {
			t.Error("expected IsEvidenceGated() to be true")
		}
	})
}

func TestGraph_SubnetQueries(t *testing.T) {
	t.Run("nil graph returns zero counts and nil subnet", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.HostCount() != 0 {
			t.Errorf("nilGraph.HostCount() = %d, want 0", nilGraph.HostCount())
		}
		if nilGraph.SubnetCount() != 0 {
			t.Errorf("nilGraph.SubnetCount() = %d, want 0", nilGraph.SubnetCount())
		}
		if nilGraph.Subnet("sub-1") != nil {
			t.Error("nilGraph.Subnet() should return nil")
		}
		if nilGraph.PrivateSubnets() != nil {
			t.Error("nilGraph.PrivateSubnets() should return nil")
		}
	})

	t.Run("populated graph returns counts and lookup", func(t *testing.T) {
		s1 := &Subnet{ID: "sub-1", Tags: map[string]string{"stave:subnet-type": "private"}}
		s2 := &Subnet{ID: "sub-2", Tags: map[string]string{"stave:subnet-type": "public"}}
		h1 := &Host{ID: "host-1", SubnetID: "sub-1"}
		g := &Graph{
			Hosts:   map[string]*Host{"host-1": h1},
			Subnets: map[string]*Subnet{"sub-1": s1, "sub-2": s2},
		}

		if g.HostCount() != 1 {
			t.Errorf("g.HostCount() = %d, want 1", g.HostCount())
		}
		if g.SubnetCount() != 2 {
			t.Errorf("g.SubnetCount() = %d, want 2", g.SubnetCount())
		}
		if g.Subnet("sub-1") != s1 {
			t.Errorf("g.Subnet(\"sub-1\") = %v, want %v", g.Subnet("sub-1"), s1)
		}
		if g.Subnet("") != nil {
			t.Error("g.Subnet(\"\") should return nil")
		}
		if g.Subnet("sub-missing") != nil {
			t.Error("g.Subnet(\"sub-missing\") should return nil")
		}
		if len(g.PrivateSubnets()) != 1 {
			t.Errorf("len(g.PrivateSubnets()) = %d, want 1", len(g.PrivateSubnets()))
		}
	})
}

func TestHost_VPCAndSubnetPredicates(t *testing.T) {
	t.Run("nil host", func(t *testing.T) {
		var nilHost *Host
		if nilHost.HasVPC() {
			t.Error("nilHost.HasVPC() should be false")
		}
		if nilHost.HasSubnet() {
			t.Error("nilHost.HasSubnet() should be false")
		}
	})

	t.Run("empty fields", func(t *testing.T) {
		h := &Host{ID: "host-1"}
		if h.HasVPC() {
			t.Error("h.HasVPC() should be false for empty VPCID")
		}
		if h.HasSubnet() {
			t.Error("h.HasSubnet() should be false for empty SubnetID")
		}
	})

	t.Run("populated fields", func(t *testing.T) {
		h := &Host{ID: "host-1", VPCID: "vpc-1", SubnetID: "sub-1"}
		if !h.HasVPC() {
			t.Error("expected HasVPC() to be true")
		}
		if !h.HasSubnet() {
			t.Error("expected HasSubnet() to be true")
		}
	})
}

func TestRoute_TargetTypePredicates(t *testing.T) {
	t.Run("NAT gateway route", func(t *testing.T) {
		r := Route{TargetType: "nat"}
		if !r.IsNATGateway() {
			t.Error("expected IsNATGateway() to be true")
		}
		if r.IsLocal() {
			t.Error("expected IsLocal() to be false")
		}
	})

	t.Run("Local route", func(t *testing.T) {
		r := Route{TargetType: "local"}
		if !r.IsLocal() {
			t.Error("expected IsLocal() to be true")
		}
		if r.IsNATGateway() {
			t.Error("expected IsNATGateway() to be false")
		}
	})
}

func TestGraph_RouteCountForSubnet(t *testing.T) {
	t.Run("nil graph or subnet returns 0 and false", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.RouteCountForSubnet(&Subnet{RouteTableID: "rt-1"}) != 0 {
			t.Error("nilGraph.RouteCountForSubnet() should be 0")
		}
		if nilGraph.HasRoutes(&Subnet{RouteTableID: "rt-1"}) {
			t.Error("nilGraph.HasRoutes() should be false")
		}

		g := &Graph{Routes: map[string][]Route{"rt-1": {{Destination: "0.0.0.0/0"}}}}
		if g.RouteCountForSubnet(nil) != 0 {
			t.Error("g.RouteCountForSubnet(nil) should be 0")
		}
		if g.HasRoutes(nil) {
			t.Error("g.HasRoutes(nil) should be false")
		}
	})

	t.Run("subnet without route table returns 0", func(t *testing.T) {
		g := &Graph{}
		sub := &Subnet{ID: "sub-1"}
		if g.RouteCountForSubnet(sub) != 0 {
			t.Errorf("g.RouteCountForSubnet() = %d, want 0", g.RouteCountForSubnet(sub))
		}
		if g.HasRoutes(sub) {
			t.Error("g.HasRoutes() should be false")
		}
	})

	t.Run("subnet with routes returns count and true", func(t *testing.T) {
		g := &Graph{
			Routes: map[string][]Route{
				"rt-1": {
					{Destination: "10.0.0.0/16", TargetType: "local"},
					{Destination: "0.0.0.0/0", TargetType: "nat", TargetID: "nat-1"},
				},
			},
		}
		sub := &Subnet{ID: "sub-1", RouteTableID: "rt-1"}
		if g.RouteCountForSubnet(sub) != 2 {
			t.Errorf("g.RouteCountForSubnet() = %d, want 2", g.RouteCountForSubnet(sub))
		}
		if !g.HasRoutes(sub) {
			t.Error("g.HasRoutes() should be true")
		}
	})
}

func Test_egressCandidatePartition_CountsAndAdd(t *testing.T) {
	t.Run("empty partition", func(t *testing.T) {
		var p egressCandidatePartition
		if !p.IsEmpty() {
			t.Error("expected IsEmpty() to be true")
		}
		if p.SinkCount() != 0 {
			t.Errorf("SinkCount() = %d, want 0", p.SinkCount())
		}
		if p.GatedCount() != 0 {
			t.Errorf("GatedCount() = %d, want 0", p.GatedCount())
		}
		if p.Total() != 0 {
			t.Errorf("Total() = %d, want 0", p.Total())
		}
	})

	t.Run("adding sink and gated candidates", func(t *testing.T) {
		var p egressCandidatePartition
		c1 := egressCandidate{
			host:   &Host{ID: "host-sink"},
			route:  Route{TargetType: "igw"},
			target: RouteTarget{Class: routeSink},
		}
		c2 := egressCandidate{
			host:   &Host{ID: "host-gated"},
			route:  Route{TargetType: "tgw"},
			target: RouteTarget{Class: routeGated},
		}

		p.add(c1)
		p.add(c2)

		if p.IsEmpty() {
			t.Error("expected IsEmpty() to be false")
		}
		if p.SinkCount() != 1 {
			t.Errorf("SinkCount() = %d, want 1", p.SinkCount())
		}
		if p.GatedCount() != 1 {
			t.Errorf("GatedCount() = %d, want 1", p.GatedCount())
		}
		if p.Total() != 2 {
			t.Errorf("Total() = %d, want 2", p.Total())
		}
	})
}

func Test_formatEgressReachabilityPrefix(t *testing.T) {
	t.Run("specific port", func(t *testing.T) {
		got := formatEgressReachabilityPrefix("iso-1", "host-2", 443)
		want := "Isolated host iso-1 can reach host-2 on port 443."
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("wildcard port 0 formats as all", func(t *testing.T) {
		got := formatEgressReachabilityPrefix("iso-1", "host-2", 0)
		want := "Isolated host iso-1 can reach host-2 on port all."
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func Test_egressCandidate_Methods(t *testing.T) {
	t.Run("HostID with nil host returns empty string", func(t *testing.T) {
		c := egressCandidate{}
		if c.HostID() != "" {
			t.Errorf("c.HostID() = %q, want empty string", c.HostID())
		}
	})

	t.Run("HostID with host returns host ID", func(t *testing.T) {
		c := egressCandidate{host: &Host{ID: "host-42"}}
		if c.HostID() != "host-42" {
			t.Errorf("c.HostID() = %q, want host-42", c.HostID())
		}
	})

	t.Run("IsSink and IsGated delegates", func(t *testing.T) {
		sink := egressCandidate{target: RouteTarget{Class: routeSink}}
		if !sink.IsSink() {
			t.Error("expected IsSink() to be true")
		}
		if sink.IsGated() {
			t.Error("expected IsGated() to be false")
		}

		gated := egressCandidate{target: RouteTarget{Class: routeGated}}
		if gated.IsSink() {
			t.Error("expected IsSink() to be false")
		}
		if !gated.IsGated() {
			t.Error("expected IsGated() to be true")
		}
	})
}

func TestHost_SafeAccessors(t *testing.T) {
	t.Run("nil host returns empty strings", func(t *testing.T) {
		var nilHost *Host
		if nilHost.SafeVPCID() != "" {
			t.Errorf("nilHost.SafeVPCID() = %q, want empty", nilHost.SafeVPCID())
		}
		if nilHost.SafeSubnetID() != "" {
			t.Errorf("nilHost.SafeSubnetID() = %q, want empty", nilHost.SafeSubnetID())
		}
	})

	t.Run("populated host returns IDs", func(t *testing.T) {
		h := &Host{ID: "host-1", VPCID: "vpc-1", SubnetID: "sub-1"}
		if h.SafeVPCID() != "vpc-1" {
			t.Errorf("h.SafeVPCID() = %q, want vpc-1", h.SafeVPCID())
		}
		if h.SafeSubnetID() != "sub-1" {
			t.Errorf("h.SafeSubnetID() = %q, want sub-1", h.SafeSubnetID())
		}
	})
}

func TestSubnet_SafeVPCID(t *testing.T) {
	t.Run("nil subnet returns empty string", func(t *testing.T) {
		var nilSub *Subnet
		if nilSub.SafeVPCID() != "" {
			t.Errorf("nilSub.SafeVPCID() = %q, want empty", nilSub.SafeVPCID())
		}
	})

	t.Run("populated subnet returns VPCID", func(t *testing.T) {
		sub := &Subnet{ID: "sub-1", VPCID: "vpc-99"}
		if sub.SafeVPCID() != "vpc-99" {
			t.Errorf("sub.SafeVPCID() = %q, want vpc-99", sub.SafeVPCID())
		}
	})
}

func TestGraph_IsPubliclyAccessibleAnyPort(t *testing.T) {
	t.Run("nil graph or host returns false", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.IsPubliclyAccessibleAnyPort(&Host{ID: "host-1"}) {
			t.Error("nilGraph.IsPubliclyAccessibleAnyPort() should be false")
		}

		g := &Graph{}
		if g.IsPubliclyAccessibleAnyPort(nil) {
			t.Error("g.IsPubliclyAccessibleAnyPort(nil) should be false")
		}
	})

	t.Run("reports true when host has internet ingress on any port", func(t *testing.T) {
		h := &Host{ID: "i-public", SGIDs: []string{"sg-http"}}
		g := &Graph{
			SGRules: map[string][]SGRule{
				"sg-http": {
					{Direction: "ingress", Protocol: "tcp", Port: 8080, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
				},
			},
		}
		if !g.IsPubliclyAccessibleAnyPort(h) {
			t.Error("expected IsPubliclyAccessibleAnyPort() to be true")
		}
	})

	t.Run("reports false when host only has internal ingress", func(t *testing.T) {
		h := &Host{ID: "i-private", SGIDs: []string{"sg-internal"}}
		g := &Graph{
			SGRules: map[string][]SGRule{
				"sg-internal": {
					{Direction: "ingress", Protocol: "tcp", Port: 8080, SourceType: "cidr", SourceValue: "10.0.0.0/8"},
				},
			},
		}
		if g.IsPubliclyAccessibleAnyPort(h) {
			t.Error("expected IsPubliclyAccessibleAnyPort() to be false for private CIDR")
		}
	})
}

func TestSubnet_IsPublic(t *testing.T) {
	t.Run("nil subnet returns false", func(t *testing.T) {
		var nilSub *Subnet
		if nilSub.IsPublic() {
			t.Error("nilSub.IsPublic() should be false")
		}
	})

	t.Run("untagged subnet returns false", func(t *testing.T) {
		s := &Subnet{}
		if s.IsPublic() {
			t.Error("expected false for untagged subnet")
		}
	})

	t.Run("publicly tagged subnet returns true", func(t *testing.T) {
		s := &Subnet{Tags: map[string]string{"stave:subnet-type": "public"}}
		if !s.IsPublic() {
			t.Error("expected true for public subnet")
		}
	})

	t.Run("private subnet returns false", func(t *testing.T) {
		s := &Subnet{Tags: map[string]string{"stave:subnet-type": "private"}}
		if s.IsPublic() {
			t.Error("expected false for private subnet")
		}
	})
}

func TestGraph_PublicSubnets(t *testing.T) {
	t.Run("nil graph returns nil", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.PublicSubnets() != nil {
			t.Error("nilGraph.PublicSubnets() should return nil")
		}
	})

	t.Run("returns only public subnets", func(t *testing.T) {
		s1 := &Subnet{ID: "sub-priv", Tags: map[string]string{"stave:subnet-type": "private"}}
		s2 := &Subnet{ID: "sub-pub", Tags: map[string]string{"stave:subnet-type": "public"}}
		g := &Graph{
			Subnets: map[string]*Subnet{
				"sub-priv": s1,
				"sub-pub":  s2,
			},
		}
		public := g.PublicSubnets()
		if len(public) != 1 || public[0] != s2 {
			t.Errorf("got %v, want [%v]", public, s2)
		}
	})
}

func TestGraph_findDatabaseTierBypass(t *testing.T) {
	t.Run("nil or empty hosts returns nil and empty reason", func(t *testing.T) {
		g := NewGraph()
		ce, reason := g.findDatabaseTierBypass(nil)
		if ce != nil || reason != "" {
			t.Errorf("got ce=%v, reason=%q; want nil, \"\"", ce, reason)
		}

		ce, reason = g.findDatabaseTierBypass([]*Host{})
		if ce != nil || reason != "" {
			t.Errorf("got ce=%v, reason=%q; want nil, \"\"", ce, reason)
		}
	})

	t.Run("returns bypass when database host has internet exposure", func(t *testing.T) {
		g := NewGraph()
		db := &Host{ID: "db-1", SGIDs: []string{"sg-db"}}
		g.SGRules["sg-db"] = []SGRule{
			{Direction: "ingress", Protocol: "tcp", Port: 5432, SourceType: "cidr", SourceValue: "0.0.0.0/0"},
		}

		ce, reason := g.findDatabaseTierBypass([]*Host{db})
		if ce == nil {
			t.Fatal("expected non-nil counterexample")
		}
		if ce.Destination != "db-1" || ce.Port != 5432 {
			t.Errorf("ce = %+v, want Destination=db-1, Port=5432", ce)
		}
		if reason == "" {
			t.Error("expected non-empty reason")
		}
	})
}

func TestRuleMatch_PathPredicates(t *testing.T) {
	t.Run("nil rule match returns false", func(t *testing.T) {
		var nilMatch *RuleMatch
		if nilMatch.IsExternal() {
			t.Error("nilMatch.IsExternal() should be false")
		}
		if nilMatch.IsCrossVPC() {
			t.Error("nilMatch.IsCrossVPC() should be false")
		}
	})

	t.Run("external match", func(t *testing.T) {
		m := &RuleMatch{PathType: "external"}
		if !m.IsExternal() {
			t.Error("expected IsExternal() to be true")
		}
		if m.IsCrossVPC() {
			t.Error("expected IsCrossVPC() to be false")
		}
	})

	t.Run("cross-vpc match", func(t *testing.T) {
		m := &RuleMatch{PathType: "cross-vpc"}
		if m.IsExternal() {
			t.Error("expected IsExternal() to be false")
		}
		if !m.IsCrossVPC() {
			t.Error("expected IsCrossVPC() to be true")
		}
	})

	t.Run("internal match (e.g. sg-ref)", func(t *testing.T) {
		m := &RuleMatch{PathType: "sg-ref"}
		if m.IsExternal() {
			t.Error("expected IsExternal() to be false")
		}
		if m.IsCrossVPC() {
			t.Error("expected IsCrossVPC() to be false")
		}
	})
}

func TestRoute_IsEgress(t *testing.T) {
	t.Run("igw is egress sink", func(t *testing.T) {
		r := Route{TargetType: "igw"}
		if !r.IsEgress() {
			t.Error("expected IsEgress() to be true for igw")
		}
	})

	t.Run("nat is egress sink", func(t *testing.T) {
		r := Route{TargetType: "nat"}
		if !r.IsEgress() {
			t.Error("expected IsEgress() to be true for nat")
		}
	})

	t.Run("local is not egress sink", func(t *testing.T) {
		r := Route{TargetType: "local"}
		if r.IsEgress() {
			t.Error("expected IsEgress() to be false for local")
		}
	})

	t.Run("tgw is not egress sink (gated)", func(t *testing.T) {
		r := Route{TargetType: "tgw"}
		if r.IsEgress() {
			t.Error("expected IsEgress() to be false for tgw")
		}
	})
}

func TestSubnet_DefaultRouteTarget(t *testing.T) {
	t.Run("nil receiver or graph returns false", func(t *testing.T) {
		var nilSub *Subnet
		var nilGraph *Graph
		if _, ok := nilSub.DefaultRouteTarget(nilGraph); ok {
			t.Error("expected false for nil subnet and graph")
		}

		g := NewGraph()
		if _, ok := nilSub.DefaultRouteTarget(g); ok {
			t.Error("expected false for nil subnet")
		}

		sub := &Subnet{ID: "sub-1"}
		if _, ok := sub.DefaultRouteTarget(nilGraph); ok {
			t.Error("expected false for nil graph")
		}
	})

	t.Run("returns formatted target when default route exists", func(t *testing.T) {
		g := NewGraph()
		sub := &Subnet{ID: "sub-1", RouteTableID: "rt-1"}
		g.Routes["rt-1"] = []Route{
			{Destination: "0.0.0.0/0", TargetType: "igw", TargetID: "igw-01"},
		}

		target, ok := sub.DefaultRouteTarget(g)
		if !ok || target != "igw:igw-01" {
			t.Errorf("got target=%q, ok=%v; want igw:igw-01, true", target, ok)
		}

		gTarget, gOk := g.SubnetDefaultRouteTarget(sub)
		if !gOk || gTarget != "igw:igw-01" {
			t.Errorf("got gTarget=%q, gOk=%v; want igw:igw-01, true", gTarget, gOk)
		}
	})
}

func TestGraph_PeeringAndTGWQueries(t *testing.T) {
	t.Run("nil graph returns 0 and false", func(t *testing.T) {
		var nilGraph *Graph
		if nilGraph.PeeringCount() != 0 {
			t.Errorf("nilGraph.PeeringCount() = %d, want 0", nilGraph.PeeringCount())
		}
		if nilGraph.HasPeerings() {
			t.Error("nilGraph.HasPeerings() should be false")
		}
		if nilGraph.TGWAttachmentCount() != 0 {
			t.Errorf("nilGraph.TGWAttachmentCount() = %d, want 0", nilGraph.TGWAttachmentCount())
		}
		if nilGraph.HasTGWAttachments() {
			t.Error("nilGraph.HasTGWAttachments() should be false")
		}
	})

	t.Run("populated graph returns counts and true", func(t *testing.T) {
		g := &Graph{
			Peerings: []VPCPeering{
				{PeeringID: "pcx-1", RequesterVPC: "vpc-a", AccepterVPC: "vpc-b"},
			},
			TGWAttachments: []TGWAttachment{
				{AttachmentID: "tgw-att-1", TransitGatewayID: "tgw-1", VPCID: "vpc-a"},
				{AttachmentID: "tgw-att-2", TransitGatewayID: "tgw-1", VPCID: "vpc-b"},
			},
		}

		if g.PeeringCount() != 1 {
			t.Errorf("g.PeeringCount() = %d, want 1", g.PeeringCount())
		}
		if !g.HasPeerings() {
			t.Error("expected HasPeerings() to be true")
		}
		if g.TGWAttachmentCount() != 2 {
			t.Errorf("g.TGWAttachmentCount() = %d, want 2", g.TGWAttachmentCount())
		}
		if !g.HasTGWAttachments() {
			t.Error("expected HasTGWAttachments() to be true")
		}
	})
}

func TestProofResult_ScopeAccessors(t *testing.T) {
	t.Run("nil result returns zeroes and false", func(t *testing.T) {
		var r *ProofResult
		if r.ScopeCount() != 0 {
			t.Errorf("r.ScopeCount() = %d, want 0", r.ScopeCount())
		}
		if r.HasScopeKey("hosts") {
			t.Error("expected r.HasScopeKey(hosts) to be false")
		}
		if r.ScopeValue("hosts") != 0 {
			t.Errorf("r.ScopeValue(hosts) = %d, want 0", r.ScopeValue("hosts"))
		}
	})

	t.Run("empty scope returns zero count and false", func(t *testing.T) {
		r := &ProofResult{}
		if r.ScopeCount() != 0 {
			t.Errorf("r.ScopeCount() = %d, want 0", r.ScopeCount())
		}
		if r.HasScopeKey("hosts") {
			t.Error("expected r.HasScopeKey(hosts) to be false")
		}
		if r.ScopeValue("hosts") != 0 {
			t.Errorf("r.ScopeValue(hosts) = %d, want 0", r.ScopeValue("hosts"))
		}
	})

	t.Run("populated scope returns count and values", func(t *testing.T) {
		r := &ProofResult{
			Scope: map[string]int{
				"hosts":     5,
				"endpoints": 2,
			},
		}
		if r.ScopeCount() != 2 {
			t.Errorf("r.ScopeCount() = %d, want 2", r.ScopeCount())
		}
		if !r.HasScopeKey("hosts") {
			t.Error("expected r.HasScopeKey(hosts) to be true")
		}
		if r.ScopeValue("hosts") != 5 {
			t.Errorf("r.ScopeValue(hosts) = %d, want 5", r.ScopeValue("hosts"))
		}
		if !r.HasScopeKey("endpoints") {
			t.Error("expected r.HasScopeKey(endpoints) to be true")
		}
		if r.ScopeValue("endpoints") != 2 {
			t.Errorf("r.ScopeValue(endpoints) = %d, want 2", r.ScopeValue("endpoints"))
		}
		if r.HasScopeKey("missing") {
			t.Error("expected r.HasScopeKey(missing) to be false")
		}
		if r.ScopeValue("missing") != 0 {
			t.Errorf("r.ScopeValue(missing) = %d, want 0", r.ScopeValue("missing"))
		}
	})
}

func Test_formatEgressRemediation(t *testing.T) {
	wantRemove := "Remove network access from i-iso to i-sink"
	if got := formatRemoveAccessRemediation("i-iso", "i-sink"); got != wantRemove {
		t.Errorf("formatRemoveAccessRemediation() = %q, want %q", got, wantRemove)
	}

	wantBypass := "Remove network access from i-iso to i-sink, or remove i-sink's internet egress route."
	if got := formatEgressBypassRemediation("i-iso", "i-sink"); got != wantBypass {
		t.Errorf("formatEgressBypassRemediation() = %q, want %q", got, wantBypass)
	}

	wantGated := "Provide observation for transit_gateway tgw-123 to settle the verdict, or remove network access from i-iso to i-sink."
	if got := formatEgressGatedRemediation("transit_gateway", "tgw-123", "i-iso", "i-sink"); got != wantGated {
		t.Errorf("formatEgressGatedRemediation() = %q, want %q", got, wantGated)
	}
}

func Test_IsSupportedProperty(t *testing.T) {
	for _, prop := range SupportedProperties {
		if !IsSupportedProperty(prop) {
			t.Errorf("expected IsSupportedProperty(%q) to be true", prop)
		}
	}
	if IsSupportedProperty("nonexistent-property") {
		t.Error("expected IsSupportedProperty(nonexistent-property) to be false")
	}
	if IsSupportedProperty("") {
		t.Error("expected IsSupportedProperty(\"\") to be false")
	}
}

func Test_SupportedPropertiesList(t *testing.T) {
	got := SupportedPropertiesList()
	for _, prop := range SupportedProperties {
		if !strings.Contains(got, prop) {
			t.Errorf("SupportedPropertiesList() = %q, missing %q", got, prop)
		}
	}
}

func Test_EnumerateResult(t *testing.T) {
	t.Run("nil result returns 0 and false", func(t *testing.T) {
		var r *EnumerateResult
		if r.PathCount() != 0 {
			t.Errorf("r.PathCount() = %d, want 0", r.PathCount())
		}
		if r.HasPaths() {
			t.Error("expected HasPaths() to be false")
		}
	})

	t.Run("empty paths", func(t *testing.T) {
		r := NewEnumerateResult("production", 22, 5, nil)
		if r.Scope != "production" || r.Port != 22 || r.ProductionHosts != 5 {
			t.Errorf("unexpected fields: %+v", r)
		}
		if r.PathCount() != 0 {
			t.Errorf("r.PathCount() = %d, want 0", r.PathCount())
		}
		if r.HasPaths() {
			t.Error("expected HasPaths() to be false")
		}
	})

	t.Run("populated paths", func(t *testing.T) {
		paths := []SSHPath{
			{Source: "h1", Destination: "h2", Port: 22, PathType: "sg-ref"},
		}
		r := NewEnumerateResult("production", 22, 5, paths)
		if r.PathCount() != 1 {
			t.Errorf("r.PathCount() = %d, want 1", r.PathCount())
		}
		if !r.HasPaths() {
			t.Error("expected HasPaths() to be true")
		}
	})
}

func TestRuleMatch_InternetSource(t *testing.T) {
	t.Run("nil match returns empty string", func(t *testing.T) {
		var m *RuleMatch
		if got := m.InternetSource(); got != "" {
			t.Errorf("m.InternetSource() = %q, want empty string", got)
		}
	})

	t.Run("populated match returns formatted internet source", func(t *testing.T) {
		m := &RuleMatch{RuleSource: "0.0.0.0/0"}
		if got := m.InternetSource(); got != "0.0.0.0/0 (internet)" {
			t.Errorf("m.InternetSource() = %q, want %q", got, "0.0.0.0/0 (internet)")
		}
	})
}

func TestHost_SecurityGroupQueries(t *testing.T) {
	t.Run("nil host returns zero and false", func(t *testing.T) {
		var h *Host
		if h.SecurityGroupCount() != 0 {
			t.Errorf("h.SecurityGroupCount() = %d, want 0", h.SecurityGroupCount())
		}
		if h.HasSecurityGroups() {
			t.Error("expected h.HasSecurityGroups() to be false")
		}
	})

	t.Run("empty host returns zero and false", func(t *testing.T) {
		h := &Host{}
		if h.SecurityGroupCount() != 0 {
			t.Errorf("h.SecurityGroupCount() = %d, want 0", h.SecurityGroupCount())
		}
		if h.HasSecurityGroups() {
			t.Error("expected h.HasSecurityGroups() to be false")
		}
	})

	t.Run("populated host returns count and true", func(t *testing.T) {
		h := &Host{SGIDs: []string{"sg-1", "sg-2"}}
		if h.SecurityGroupCount() != 2 {
			t.Errorf("h.SecurityGroupCount() = %d, want 2", h.SecurityGroupCount())
		}
		if !h.HasSecurityGroups() {
			t.Error("expected h.HasSecurityGroups() to be true")
		}
	})
}

func TestSGRule_IsEgressAndInternetCIDR(t *testing.T) {
	t.Run("IsEgress", func(t *testing.T) {
		egress := SGRule{Direction: "egress"}
		ingress := SGRule{Direction: "ingress"}
		if !egress.IsEgress() {
			t.Error("expected egress.IsEgress() to be true")
		}
		if ingress.IsEgress() {
			t.Error("expected ingress.IsEgress() to be false")
		}
	})

	t.Run("IsInternetCIDR", func(t *testing.T) {
		v4 := SGRule{SourceType: "cidr", SourceValue: "0.0.0.0/0"}
		v6 := SGRule{SourceType: "cidr", SourceValue: "::/0"}
		internal := SGRule{SourceType: "cidr", SourceValue: "10.0.0.0/8"}
		sg := SGRule{SourceType: "sg", SourceValue: "0.0.0.0/0"}

		if !v4.IsInternetCIDR() {
			t.Error("expected 0.0.0.0/0 to be internet CIDR")
		}
		if !v6.IsInternetCIDR() {
			t.Error("expected ::/0 to be internet CIDR")
		}
		if internal.IsInternetCIDR() {
			t.Error("expected 10.0.0.0/8 not to be internet CIDR")
		}
		if sg.IsInternetCIDR() {
			t.Error("expected sg source type not to be internet CIDR")
		}
	})
}

func TestRoute_IsVPCEndpointAndTransitGateway(t *testing.T) {
	vpce := Route{TargetType: "vpce"}
	tgw := Route{TargetType: "tgw"}
	other := Route{TargetType: "nat"}

	if !vpce.IsVPCEndpoint() {
		t.Error("expected vpce.IsVPCEndpoint() to be true")
	}
	if other.IsVPCEndpoint() {
		t.Error("expected other.IsVPCEndpoint() to be false")
	}

	if !tgw.IsTransitGateway() {
		t.Error("expected tgw.IsTransitGateway() to be true")
	}
	if other.IsTransitGateway() {
		t.Error("expected other.IsTransitGateway() to be false")
	}
}

func Test_CounterexampleConstructors_SafeAccessors(t *testing.T) {
	match := &RuleMatch{
		SecurityGroupID: "sg-test",
		RuleSource:      "10.0.0.0/8",
		PathType:        "cidr",
		Port:            22,
	}

	t.Run("newInternalBastionBypassCounterexample nil checks", func(t *testing.T) {
		if newInternalBastionBypassCounterexample(nil, nil, 22, match, nil) != nil {
			t.Error("expected nil counterexample on nil src and dst")
		}
		src := &Host{ID: "src-1"}
		dst := &Host{ID: "dst-1"}
		ce := newInternalBastionBypassCounterexample(src, dst, 22, match, nil)
		if ce == nil || ce.Source != "src-1" || ce.Destination != "dst-1" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})

	t.Run("newExternalBypassCounterexample nil checks", func(t *testing.T) {
		if newExternalBypassCounterexample(nil, 22, match) != nil {
			t.Error("expected nil on nil dst")
		}
		dst := &Host{ID: "dst-1"}
		ce := newExternalBypassCounterexample(dst, 22, match)
		if ce == nil || ce.Destination != "dst-1" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})

	t.Run("newCrossEnvBypassCounterexample nil checks", func(t *testing.T) {
		if newCrossEnvBypassCounterexample(nil, nil, match) != nil {
			t.Error("expected nil on nil src/dst")
		}
		src := &Host{ID: "src-1", Tags: map[string]string{"stave:environment": "production"}}
		dst := &Host{ID: "dst-1", Tags: map[string]string{"stave:environment": "development"}}
		ce := newCrossEnvBypassCounterexample(src, dst, match)
		if ce == nil || ce.Source != "src-1" || ce.Destination != "dst-1" {
			t.Errorf("unexpected counterexample: %+v", ce)
		}
	})
}

func Test_formatFirewallBypass(t *testing.T) {
	wantExp := "Subnet subnet-1 has a 0.0.0.0/0 route to IGW igw-1 in route table rtb-1 without passing through a Network Firewall endpoint."
	if got := formatFirewallBypassExplanation("subnet-1", "0.0.0.0/0", "igw-1", "rtb-1"); got != wantExp {
		t.Errorf("formatFirewallBypassExplanation() = %q, want %q", got, wantExp)
	}

	wantRem := "Change the 0.0.0.0/0 route in rtb-1 to target a Network Firewall endpoint instead of igw-1."
	if got := formatFirewallBypassRemediation("0.0.0.0/0", "rtb-1", "igw-1"); got != wantRem {
		t.Errorf("formatFirewallBypassRemediation() = %q, want %q", got, wantRem)
	}
}

func TestGraph_ReachabilityPath(t *testing.T) {
	t.Run("nil graph or empty slices return nil", func(t *testing.T) {
		var g *Graph
		if src, dst, match := g.ReachabilityPath(nil, nil, 0); match != nil || src != nil || dst != nil {
			t.Error("expected all nils on nil graph")
		}
		g = NewGraph()
		if src, dst, match := g.ReachabilityPath(nil, nil, 0); match != nil || src != nil || dst != nil {
			t.Error("expected all nils on nil sources")
		}
	})

	t.Run("port 0 matches any port and port > 0 matches specific port", func(t *testing.T) {
		g := NewGraph()
		src := &Host{ID: "src", SGIDs: []string{"sg-src"}}
		dst := &Host{ID: "dst", SGIDs: []string{"sg-dst"}}
		g.Hosts["src"] = src
		g.Hosts["dst"] = dst
		g.SGRules["sg-dst"] = []SGRule{
			{Direction: "ingress", SourceType: "sg", SourceValue: "sg-src", Port: 8080},
		}

		// Port 0 should find reachability on 8080
		s, d, m := g.ReachabilityPath([]*Host{src}, []*Host{dst}, 0)
		if m == nil || s != src || d != dst || m.Port != 8080 {
			t.Errorf("unexpected match: s=%v, d=%v, m=%v", s, d, m)
		}

		// Port 8080 should find reachability
		s, d, m = g.ReachabilityPath([]*Host{src}, []*Host{dst}, 8080)
		if m == nil || s != src || d != dst || m.Port != 8080 {
			t.Errorf("unexpected match: s=%v, d=%v, m=%v", s, d, m)
		}

		// Port 22 should NOT match
		s, d, m = g.ReachabilityPath([]*Host{src}, []*Host{dst}, 22)
		if m != nil {
			t.Errorf("expected no match on port 22, got %+v", m)
		}
	})
}

func TestSSHPath_FormatEntryAndIsCrossVPC(t *testing.T) {
	p := SSHPath{
		Source:      "src-1",
		Destination: "dst-1",
		PathType:    "cross-vpc",
		RuleSG:      "sg-test",
		RuleSource:  "sg:sg-other",
	}

	wantEntry := "  1. src-1 → dst-1  [cross-vpc]  sg:sg-test  via:sg:sg-other"
	if got := p.FormatEntry(1); got != wantEntry {
		t.Errorf("p.FormatEntry(1) = %q, want %q", got, wantEntry)
	}

	if !p.IsCrossVPC() {
		t.Error("expected p.IsCrossVPC() to be true")
	}

	p2 := SSHPath{PathType: "sg-ref"}
	if p2.IsCrossVPC() {
		t.Error("expected p2.IsCrossVPC() to be false")
	}
}

func TestSubnet_SafeRouteTableID(t *testing.T) {
	t.Run("nil subnet returns empty string", func(t *testing.T) {
		var s *Subnet
		if got := s.SafeRouteTableID(); got != "" {
			t.Errorf("s.SafeRouteTableID() = %q, want empty string", got)
		}
		if s.HasRouteTable() {
			t.Error("expected nil subnet HasRouteTable() to be false")
		}
	})

	t.Run("empty subnet returns empty string", func(t *testing.T) {
		s := &Subnet{}
		if got := s.SafeRouteTableID(); got != "" {
			t.Errorf("s.SafeRouteTableID() = %q, want empty string", got)
		}
		if s.HasRouteTable() {
			t.Error("expected empty subnet HasRouteTable() to be false")
		}
	})

	t.Run("populated subnet returns route table ID", func(t *testing.T) {
		s := &Subnet{RouteTableID: "rtb-123"}
		if got := s.SafeRouteTableID(); got != "rtb-123" {
			t.Errorf("s.SafeRouteTableID() = %q, want rtb-123", got)
		}
		if !s.HasRouteTable() {
			t.Error("expected populated subnet HasRouteTable() to be true")
		}
	})
}

func TestGraph_SubsetCounts(t *testing.T) {
	t.Run("nil graph returns 0 counts", func(t *testing.T) {
		var g *Graph
		if g.ProductionHostCount() != 0 || g.BastionHostCount() != 0 ||
			g.DevelopmentHostCount() != 0 || g.DatabaseHostCount() != 0 ||
			g.IsolatedHostCount() != 0 || g.PrivateSubnetCount() != 0 ||
			g.PublicSubnetCount() != 0 {
			t.Error("expected all zero counts on nil graph")
		}
	})

	t.Run("populated graph returns matching counts", func(t *testing.T) {
		g := NewGraph()
		g.Hosts["prod-1"] = &Host{ID: "prod-1", Tags: map[string]string{"stave:environment": "production"}}
		g.Hosts["bastion-1"] = &Host{ID: "bastion-1", Tags: map[string]string{"stave:role": "bastion"}}
		g.Hosts["dev-1"] = &Host{ID: "dev-1", Tags: map[string]string{"stave:environment": "development"}}
		g.Hosts["db-1"] = &Host{ID: "db-1", Tags: map[string]string{"stave:tier": "database"}}
		g.Hosts["iso-1"] = &Host{ID: "iso-1", Tags: map[string]string{"stave:network-zone": "isolated"}}

		g.Subnets["sub-priv"] = &Subnet{ID: "sub-priv", Tags: map[string]string{"stave:subnet-type": "private"}}
		g.Subnets["sub-pub"] = &Subnet{ID: "sub-pub", Tags: map[string]string{"stave:subnet-type": "public"}}

		if g.ProductionHostCount() != 1 {
			t.Errorf("ProductionHostCount() = %d, want 1", g.ProductionHostCount())
		}
		if g.BastionHostCount() != 1 {
			t.Errorf("BastionHostCount() = %d, want 1", g.BastionHostCount())
		}
		if g.DevelopmentHostCount() != 1 {
			t.Errorf("DevelopmentHostCount() = %d, want 1", g.DevelopmentHostCount())
		}
		if g.DatabaseHostCount() != 1 {
			t.Errorf("DatabaseHostCount() = %d, want 1", g.DatabaseHostCount())
		}
		if g.IsolatedHostCount() != 1 {
			t.Errorf("IsolatedHostCount() = %d, want 1", g.IsolatedHostCount())
		}
		if g.PrivateSubnetCount() != 1 {
			t.Errorf("PrivateSubnetCount() = %d, want 1", g.PrivateSubnetCount())
		}
		if g.PublicSubnetCount() != 1 {
			t.Errorf("PublicSubnetCount() = %d, want 1", g.PublicSubnetCount())
		}
	})
}

func Test_formatTransitiveExplanationAndSource(t *testing.T) {
	wantSource := "hop-1 -> relay-1"
	if got := formatTransitivePathSource("hop-1", "relay-1"); got != wantSource {
		t.Errorf("formatTransitivePathSource() = %q, want %q", got, wantSource)
	}

	wantExp := "External host can reach production host prod-1 on port 22. Two-hop path: internet -> relay-1 -> prod-1."
	if got := formatTransitiveExplanation("External host", "prod-1", "internet", "relay-1", 22); got != wantExp {
		t.Errorf("formatTransitiveExplanation() = %q, want %q", got, wantExp)
	}
}

func Test_formatTransitiveRemediation(t *testing.T) {
	wantInternet := "Remove SSH ingress from 0.0.0.0/0 on relay-1 or remove its access to production host prod-1."
	if got := formatTransitiveInternetRemediation("0.0.0.0/0", "relay-1", "prod-1"); got != wantInternet {
		t.Errorf("formatTransitiveInternetRemediation() = %q, want %q", got, wantInternet)
	}

	wantInternal := "Remove SSH access from src-1 to relay-1 or from relay-1 to production host prod-1."
	if got := formatTransitiveInternalRemediation("src-1", "relay-1", "prod-1"); got != wantInternal {
		t.Errorf("formatTransitiveInternalRemediation() = %q, want %q", got, wantInternal)
	}
}

func Test_RouteTargetConstructors(t *testing.T) {
	sink := newSinkRouteTarget("igw-1")
	if !sink.IsSink() || sink.IsGated() || sink.IsNonSink() || sink.TargetID != "igw-1" {
		t.Errorf("newSinkRouteTarget() = %+v, want IsSink()=true", sink)
	}

	nonSink := newNonSinkRouteTarget("local")
	if !nonSink.IsNonSink() || nonSink.IsSink() || nonSink.IsGated() || nonSink.TargetID != "local" {
		t.Errorf("newNonSinkRouteTarget() = %+v, want IsNonSink()=true", nonSink)
	}

	gated := newGatedRouteTarget("test reason", "tgw-1")
	if !gated.IsGated() || gated.IsSink() || gated.IsNonSink() || gated.TargetID != "tgw-1" || gated.Reason != "test reason" {
		t.Errorf("newGatedRouteTarget() = %+v, want IsGated()=true", gated)
	}
}

func Test_intProp(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want int
	}{
		{"nil map", nil, "port", 0},
		{"missing key", map[string]any{}, "port", 0},
		{"int value", map[string]any{"port": 22}, "port", 22},
		{"float64 value", map[string]any{"port": float64(80)}, "port", 80},
		{"int64 value", map[string]any{"port": int64(443)}, "port", 443},
		{"string value", map[string]any{"port": "22"}, "port", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := intProp(tt.m, tt.key); got != tt.want {
				t.Errorf("intProp(%v, %q) = %d, want %d", tt.m, tt.key, got, tt.want)
			}
		})
	}
}

func Test_formatDatabaseExplanationsAndRemediations(t *testing.T) {
	wantCrossExp := "Host i-app (vpc:vpc-1) can reach database host i-db (vpc:vpc-2) via peering."
	if got := formatCrossVPCDatabaseExplanation("i-app", "vpc-1", "i-db", "vpc-2", "peering"); got != wantCrossExp {
		t.Errorf("formatCrossVPCDatabaseExplanation() = %q, want %q", got, wantCrossExp)
	}

	wantCrossRem := "Remove cross-VPC ingress to database SG sg-db. Restrict to application-tier SG references within the same VPC."
	if got := formatCrossVPCDatabaseRemediation("sg-db"); got != wantCrossRem {
		t.Errorf("formatCrossVPCDatabaseRemediation() = %q, want %q", got, wantCrossRem)
	}

	wantInternetExp := "Database host i-db accepts traffic from 0.0.0.0/0 on port 5432 via sg-db."
	if got := formatInternetDatabaseExplanation("i-db", "0.0.0.0/0", 5432, "sg-db"); got != wantInternetExp {
		t.Errorf("formatInternetDatabaseExplanation() = %q, want %q", got, wantInternetExp)
	}

	wantInternetRem := "Remove internet ingress on sg-db. Database hosts must not be reachable from the internet."
	if got := formatInternetDatabaseRemediation("sg-db"); got != wantInternetRem {
		t.Errorf("formatInternetDatabaseRemediation() = %q, want %q", got, wantInternetRem)
	}
}

func Test_formatCrossEnvExplanationAndRemediation(t *testing.T) {
	wantExp := "Host prod-1 (production) can reach dev-1 (development) via peering."
	if got := formatCrossEnvExplanation("prod-1", "production", "dev-1", "development", "peering"); got != wantExp {
		t.Errorf("formatCrossEnvExplanation() = %q, want %q", got, wantExp)
	}

	wantRem := "Remove cross-environment ingress rule on sg-cross. Ensure production and development VPCs have no peering or broad CIDR rules."
	if got := formatCrossEnvRemediation("sg-cross"); got != wantRem {
		t.Errorf("formatCrossEnvRemediation() = %q, want %q", got, wantRem)
	}
}

func Test_formatTransitiveHopLead(t *testing.T) {
	wantInternet := "Host relay-1 is SSH-accessible from the internet and"
	if got := formatTransitiveInternetHopLead("relay-1"); got != wantInternet {
		t.Errorf("formatTransitiveInternetHopLead() = %q, want %q", got, wantInternet)
	}

	wantInternal := "Host src-1 can reach relay-1, which"
	if got := formatTransitiveInternalHopLead("src-1", "relay-1"); got != wantInternal {
		t.Errorf("formatTransitiveInternalHopLead() = %q, want %q", got, wantInternal)
	}
}

func TestGraph_HostAndHasHostAndHasSubnet(t *testing.T) {
	var nilGraph *Graph
	if nilGraph.Host("i-1") != nil {
		t.Error("expected nil host from nil graph")
	}
	if nilGraph.HasHost("i-1") {
		t.Error("expected false HasHost from nil graph")
	}
	if nilGraph.HasSubnet("sub-1") {
		t.Error("expected false HasSubnet from nil graph")
	}

	g := NewGraph()
	if g.Host("") != nil || g.HasHost("") || g.HasSubnet("") {
		t.Error("expected nil / false on empty ID")
	}

	h := &Host{ID: "i-host1"}
	s := &Subnet{ID: "sub-1"}
	g.Hosts[h.ID] = h
	g.Subnets[s.ID] = s

	if got := g.Host("i-host1"); got != h {
		t.Errorf("g.Host(i-host1) = %v, want %v", got, h)
	}
	if !g.HasHost("i-host1") {
		t.Error("expected g.HasHost(i-host1) to be true")
	}
	if g.HasHost("i-missing") {
		t.Error("expected g.HasHost(i-missing) to be false")
	}

	if !g.HasSubnet("sub-1") {
		t.Error("expected g.HasSubnet(sub-1) to be true")
	}
	if g.HasSubnet("sub-missing") {
		t.Error("expected g.HasSubnet(sub-missing) to be false")
	}
}

func Test_formatEgressBypassExplanation(t *testing.T) {
	want := "Isolated host iso-1 can reach host-1 on port 443. host-1's subnet routes 0.0.0.0/0 to nat:nat-1. Two-hop path: iso-1 → host-1 → internet."
	if got := formatEgressBypassExplanation("iso-1", "host-1", "0.0.0.0/0", "nat:nat-1", 443); got != want {
		t.Errorf("formatEgressBypassExplanation() = %q, want %q", got, want)
	}
}

func Test_formatEgressGatedExplanation(t *testing.T) {
	want := "Isolated host iso-1 can reach host-1 on port 443. host-1's subnet routes 0.0.0.0/0 to tgw:tgw-1 (TGW route table not resolved)."
	if got := formatEgressGatedExplanation("iso-1", "host-1", "0.0.0.0/0", "tgw:tgw-1", "TGW route table not resolved", 443); got != want {
		t.Errorf("formatEgressGatedExplanation() = %q, want %q", got, want)
	}
}

func TestGraph_RouteTableCountAndHasRouteTables(t *testing.T) {
	var nilGraph *Graph
	if nilGraph.RouteTableCount() != 0 {
		t.Errorf("nilGraph.RouteTableCount() = %d, want 0", nilGraph.RouteTableCount())
	}
	if nilGraph.HasRouteTables() {
		t.Error("expected false HasRouteTables from nil graph")
	}

	g := NewGraph()
	if g.RouteTableCount() != 0 {
		t.Errorf("empty graph RouteTableCount() = %d, want 0", g.RouteTableCount())
	}
	if g.HasRouteTables() {
		t.Error("expected false HasRouteTables on empty graph")
	}

	g.Routes["rt-1"] = []Route{{Destination: "0.0.0.0/0", TargetType: "igw"}}
	if g.RouteTableCount() != 1 {
		t.Errorf("g.RouteTableCount() = %d, want 1", g.RouteTableCount())
	}
	if !g.HasRouteTables() {
		t.Error("expected true HasRouteTables")
	}
}

func Test_formatSSHExplanations(t *testing.T) {
	wantExt := "Production host prod-1 accepts SSH from the internet (0.0.0.0/0) on sg-1. No bastion in the path."
	if got := formatExternalSSHExplanation("prod-1", "0.0.0.0/0", "sg-1"); got != wantExt {
		t.Errorf("formatExternalSSHExplanation() = %q, want %q", got, wantExt)
	}

	wantCross := "Host src-1 (vpc:vpc-1) can SSH to production host prod-1 (vpc:vpc-2) via VPC peering. Security group sg-1 allows SSH from 10.0.0.0/8. No bastion in the path."
	if got := formatCrossVPCSSHExplanation("src-1", "vpc-1", "prod-1", "vpc-2", "sg-1", "10.0.0.0/8"); got != wantCross {
		t.Errorf("formatCrossVPCSSHExplanation() = %q, want %q", got, wantCross)
	}

	wantInt := "Host src-1 can SSH to production host prod-1 via sg-1 allowing SSH from 10.0.0.0/8. No bastion in the path."
	if got := formatInternalSSHExplanation("src-1", "prod-1", "sg-1", "10.0.0.0/8"); got != wantInt {
		t.Errorf("formatInternalSSHExplanation() = %q, want %q", got, wantInt)
	}
}


















