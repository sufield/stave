package network

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
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
	ok, pathType := g.CanReach("i-src", "i-dst", 22)
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
