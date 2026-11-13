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

func TestHost_IsCandidateRelay(t *testing.T) {
	var nilHost *Host
	dst := &Host{ID: "i-prod", Tags: map[string]string{"stave:environment": "production"}}
	prodRelay := &Host{ID: "i-prod-2", Tags: map[string]string{"stave:environment": "production"}}
	bastionRelay := &Host{ID: "i-bastion", Tags: map[string]string{"stave:role": "bastion"}}
	stagingRelay := &Host{ID: "i-staging", Tags: map[string]string{"stave:environment": "staging"}}
	devRelay := &Host{ID: "i-dev", Tags: map[string]string{"stave:environment": "development"}}
	untaggedRelay := &Host{ID: "i-unknown"}

	if nilHost.IsCandidateRelay(dst) {
		t.Error("nil host should not be candidate relay")
	}
	if stagingRelay.IsCandidateRelay(nil) {
		t.Error("relay to nil destination should not be candidate relay")
	}
	if dst.IsCandidateRelay(dst) {
		t.Error("destination itself should not be candidate relay to itself")
	}
	sameDstClone := &Host{ID: "i-prod"}
	if sameDstClone.IsCandidateRelay(dst) {
		t.Error("host matching destination ID should not be candidate relay")
	}
	if prodRelay.IsCandidateRelay(dst) {
		t.Error("production host should not be candidate relay")
	}
	if bastionRelay.IsCandidateRelay(dst) {
		t.Error("authorized bastion should not be candidate relay")
	}
	if !stagingRelay.IsCandidateRelay(dst) {
		t.Error("staging non-bastion host should be candidate relay")
	}
	if !devRelay.IsCandidateRelay(dst) {
		t.Error("development non-bastion host should be candidate relay")
	}
	if !untaggedRelay.IsCandidateRelay(dst) {
		t.Error("untagged non-bastion host should be candidate relay")
	}

	// Multi-target checks (e.g. src checked against relay and dst)
	if stagingRelay.IsCandidateRelay() {
		t.Error("host with no target specified should not be candidate relay")
	}
	if !stagingRelay.IsCandidateRelay(devRelay, dst) {
		t.Error("staging host should be candidate relay to distinct relay and dst")
	}
	if stagingRelay.IsCandidateRelay(stagingRelay, dst) {
		t.Error("staging host matching first target should not be candidate relay")
	}
	if stagingRelay.IsCandidateRelay(devRelay, stagingRelay) {
		t.Error("staging host matching second target should not be candidate relay")
	}
	if stagingRelay.IsCandidateRelay(devRelay, nil) {
		t.Error("host with nil target in multi-target list should not be candidate relay")
	}
	if prodRelay.IsCandidateRelay(devRelay, dst) {
		t.Error("production host should not be candidate relay in multi-target check")
	}
	if bastionRelay.IsCandidateRelay(devRelay, dst) {
		t.Error("bastion host should not be candidate relay in multi-target check")
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





