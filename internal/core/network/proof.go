// Package network proves network safety properties over concrete VPC
// snapshots using exhaustive graph search.
//
// The provers use SAT/UNSAT vocabulary because the questions are
// satisfiability questions ("does there exist a path that bypasses the
// bastion?"), but the solver is brute-force enumeration, not an SMT
// engine. This is deliberate:
//
//   - The graph is small (tens–hundreds of hosts/rules); exhaustive
//     search is faster than Z3's formula-building overhead.
//   - No symbolic reasoning is needed — predicates are concrete SG rule
//     lookups, not constraint intersection.
//   - A three-valued verdict (SAT / UNSAT / EVIDENCE_GATED) is needed
//     when the snapshot is incomplete; Z3 is two-valued.
//   - Counterexamples are built inline with infrastructure names; no
//     model-extraction step.
//   - Zero native dependencies — no CGo, no subprocess, single binary.
//
// Z3 is used elsewhere (semantic-diff) for genuinely symbolic work:
// checking CEL predicate equivalence, where enumeration is impossible.
package network

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ProofResult is the outcome of a network safety property proof.
type ProofResult struct {
	Property        string          `json:"property"`
	Result          string          `json:"result"` // "UNSAT" | "SAT" | "EVIDENCE_GATED"
	Interpretation  string          `json:"interpretation"`
	ProductionHosts int             `json:"production_hosts,omitempty"`
	BastionHosts    int             `json:"bastion_hosts,omitempty"`
	SSHPaths        int             `json:"ssh_paths,omitempty"`
	Scope           map[string]int  `json:"scope,omitempty"`
	Counterexample  *Counterexample `json:"counterexample,omitempty"`
	SolveTimeMs     int64           `json:"solve_time_ms"`
}

func (r *ProofResult) finish(result, interpretation string, ce *Counterexample, start time.Time) (*ProofResult, error) {
	r.Result = result
	r.Interpretation = interpretation
	r.Counterexample = ce
	r.SolveTimeMs = time.Since(start).Milliseconds()
	return r, nil
}

func (r *ProofResult) sat(ce *Counterexample, interpretation string, start time.Time) (*ProofResult, error) {
	return r.finish("SAT", interpretation, ce, start)
}

func (r *ProofResult) unsat(interpretation string, start time.Time) (*ProofResult, error) {
	return r.finish("UNSAT", interpretation, nil, start)
}

func (r *ProofResult) gated(ce *Counterexample, interpretation string, start time.Time) (*ProofResult, error) {
	return r.finish("EVIDENCE_GATED", interpretation, ce, start)
}

func newProofResult(property string, scope map[string]int) *ProofResult {
	return &ProofResult{
		Property: property,
		Scope:    scope,
	}
}

func newBastionProofResult(property string, prodHosts, bastionHosts int) *ProofResult {
	return &ProofResult{
		Property:        property,
		ProductionHosts: prodHosts,
		BastionHosts:    bastionHosts,
	}
}

// SecurityGroupIngressExposure captures evidence where network traffic is admitted
// across isolation boundaries by a security group rule.
type SecurityGroupIngressExposure struct {
	SecurityGroupID string `json:"security_group_id"`
	RuleSource      string `json:"rule_source"`
}

// UnprotectedRoutePath captures evidence where traffic is routed directly to
// an uninspected egress gateway (such as an internet gateway) bypassing firewall controls.
type UnprotectedRoutePath struct {
	RouteTableID string `json:"route_table_id"`
	Destination  string `json:"destination"`
}

// Counterexample is a concrete bastion bypass or safety property violation path.
type Counterexample struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	PathType    string `json:"path_type"`
	RuleSG      string `json:"rule_sg,omitempty"`
	RuleSource  string `json:"rule_source,omitempty"`
	Explanation string `json:"explanation"`
	Remediation string `json:"remediation"`

	SGExposure *SecurityGroupIngressExposure `json:"sg_exposure,omitempty"`
	RoutePath  *UnprotectedRoutePath         `json:"route_path,omitempty"`
}

// newSGCounterexample constructs a Counterexample for a security group ingress violation,
// populating the SGExposure model alongside the legacy RuleSG and RuleSource fields.
func newSGCounterexample(source, destination string, port int, pathType string, match *RuleMatch, explanation, remediation string) *Counterexample {
	ce := &Counterexample{
		Source:      source,
		Destination: destination,
		Port:        port,
		PathType:    pathType,
		Explanation: explanation,
		Remediation: remediation,
	}
	if match != nil {
		ce.RuleSG = match.SecurityGroupID
		ce.RuleSource = match.RuleSource
		ce.SGExposure = &SecurityGroupIngressExposure{
			SecurityGroupID: match.SecurityGroupID,
			RuleSource:      match.RuleSource,
		}
	}
	return ce
}

// newRouteCounterexample constructs a Counterexample for an unprotected route violation,
// populating the RoutePath model with route table and destination CIDR evidence.
func newRouteCounterexample(sub *Subnet, route Route, pathType, explanation, remediation string) *Counterexample {
	ce := &Counterexample{
		Destination: route.TargetID,
		PathType:    pathType,
		Explanation: explanation,
		Remediation: remediation,
	}
	if sub != nil {
		ce.Source = sub.ID
		ce.RoutePath = &UnprotectedRoutePath{
			RouteTableID: sub.RouteTableID,
			Destination:  route.Destination,
		}
	}
	return ce
}

// newTransitiveCounterexample constructs a Counterexample for a two-hop transitive path violation
// (hop1 -> relay -> dst), formatting the explanation and remediation consistently.
func newTransitiveCounterexample(hop1ID, hop1Path, hop1Lead string, relay, dst *Host, port int, relayMatch *RuleMatch, remediation string) *Counterexample {
	relayID, dstID := "", ""
	if relay != nil {
		relayID = relay.ID
	}
	if dst != nil {
		dstID = dst.ID
	}
	explanation := hop1Lead + " can reach production host " + dstID + " on port " + strconv.Itoa(port) + ". Two-hop path: " + hop1Path + " -> " + relayID + " -> " + dstID + "."
	return newSGCounterexample(
		hop1ID+" -> "+relayID, dstID, port, "transitive", relayMatch,
		explanation, remediation,
	)
}

// SSHPath describes a network path to a host on port 22.
type SSHPath struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	PathType    string `json:"path_type"` // "sg-ref" | "cidr" | "cross-vpc"
	RuleSG      string `json:"rule_sg"`
	RuleSource  string `json:"rule_source"`
}

// EnumerateResult is the output of SSH entry point enumeration.
type EnumerateResult struct {
	Scope           string    `json:"scope"`
	Port            int       `json:"port"`
	ProductionHosts int       `json:"production_hosts"`
	Paths           []SSHPath `json:"paths"`
}

// ErrVacuousProof is returned when a proof cannot run because the
// scope sets (production hosts, bastion hosts) are empty.
var ErrVacuousProof = errors.New("vacuous proof")

func vacuousErr(format string, a ...any) error {
	if len(a) > 0 {
		format = fmt.Sprintf(format, a...)
	}
	return fmt.Errorf("%w: %s", ErrVacuousProof, format)
}

// ProveBastionSSH checks whether all SSH paths to production hosts
// traverse a bastion. Returns UNSAT if bastion routing holds,
// SAT with a counterexample if a bypass exists.
//
// Returns ErrVacuousProof when production or bastion hosts are empty —
// the property cannot be proved without both scope sets populated.
func (g *Graph) ProveBastionSSH(port int) (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	bastions := g.BastionHosts()

	if len(prod) == 0 {
		return nil, vacuousErr("no hosts tagged stave:environment=production — cannot prove bastion routing")
	}
	if len(bastions) == 0 {
		return nil, vacuousErr("no hosts tagged stave:role=bastion — cannot prove bastion routing")
	}

	result := newBastionProofResult("bastion-ssh", len(prod), len(bastions))

	// Find all SSH paths to production from non-bastion, non-production sources.
	for _, dst := range prod {
		for _, src := range g.allHosts() {
			if src.IsTrusted(dst) {
				continue
			}
			if match := g.Reachability(src, dst, port); match != nil {
				result.SSHPaths++
				ce := newSGCounterexample(
					src.ID, dst.ID, port, match.PathType, match,
					match.Explanation(src, dst),
					match.Remediation(bastions),
				)
				return result.sat(ce, "Bastion bypass exists — a non-bastion host can SSH to production without traversing a bastion.", start)
			}
		}

		// Check external entry (0.0.0.0/0).
		if ce := g.findExternalBypass(dst, port); ce != nil {
			result.SSHPaths++
			return result.sat(ce, "Bastion bypass exists — production host is directly SSH-accessible from the internet.", start)
		}
	}

	return result.unsat("All SSH paths to production traverse a bastion host.", start)
}

func (g *Graph) findExternalBypass(dst *Host, port int) *Counterexample {
	match := g.findInternetRule(dst, port)
	if match == nil {
		return nil
	}
	return newSGCounterexample(
		match.RuleSource+" (internet)", dst.ID, port, match.PathType, match,
		match.Explanation(nil, dst),
		match.Remediation(nil),
	)
}

// ProveProdDevIsolation checks that no network path exists between
// production and development environments. Returns UNSAT if isolation
// holds, SAT with a counterexample if a cross-environment path exists.
func (g *Graph) ProveProdDevIsolation() (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	dev := g.DevelopmentHosts()

	if len(prod) == 0 {
		return nil, vacuousErr("no hosts tagged stave:environment=production")
	}
	if len(dev) == 0 {
		return nil, vacuousErr("no hosts tagged stave:environment=development")
	}

	result := newProofResult("prod-dev-isolation", map[string]int{"production_hosts": len(prod), "development_hosts": len(dev)})

	// Check both directions: prod→dev and dev→prod.
	pairs := [][2][]*Host{{prod, dev}, {dev, prod}}
	for _, pair := range pairs {
		for _, src := range pair[0] {
			for _, dst := range pair[1] {
				match := g.ReachabilityAnyPort(src, dst)
				if match == nil {
					continue
				}
				ce := newSGCounterexample(
					src.ID, dst.ID, match.Port, match.PathType, match,
					"Host "+src.ID+" ("+src.Environment()+") can reach "+dst.ID+" ("+dst.Environment()+") via "+match.PathType+".",
					"Remove cross-environment ingress rule on "+match.SecurityGroupID+". Ensure production and development VPCs have no peering or broad CIDR rules.",
				)
				return result.sat(ce, "Production-development isolation violated — a cross-environment path exists.", start)
			}
		}
	}

	return result.unsat("Production and development environments are network-isolated.", start)
}

// ProveDatabaseIsolation checks that no host outside the database VPC
// can reach a database-tier host. Returns UNSAT if isolation holds,
// SAT with a counterexample if an external path exists.
func (g *Graph) ProveDatabaseIsolation() (*ProofResult, error) {
	start := time.Now()

	dbHosts := g.DatabaseHosts()
	if len(dbHosts) == 0 {
		return nil, vacuousErr("no hosts tagged stave:tier=database")
	}

	result := newProofResult("database-isolation", map[string]int{"database_hosts": len(dbHosts)})

	for _, dst := range dbHosts {
		// Check cross-VPC reachability from any non-same-VPC host.
		for _, src := range g.allHosts() {
			if src.IsInternal(dst) {
				continue
			}
			if match := g.ReachabilityAnyPort(src, dst); match != nil {
				ce := newSGCounterexample(
					src.ID, dst.ID, match.Port, match.PathType, match,
					"Host "+src.ID+" (vpc:"+src.VPCID+") can reach database host "+dst.ID+" (vpc:"+dst.VPCID+") via "+match.PathType+".",
					"Remove cross-VPC ingress to database SG "+match.SecurityGroupID+". Restrict to application-tier SG references within the same VPC.",
				)
				return result.sat(ce, "Database isolation violated — a host outside the database VPC can reach a database host.", start)
			}
		}

		// Check external entry (0.0.0.0/0 or ::/0 on any port).
		if match := g.findInternetRuleAnyPort(dst); match != nil {
			ce := newSGCounterexample(
				match.RuleSource+" (internet)", dst.ID, match.Port, match.PathType, match,
				"Database host "+dst.ID+" accepts traffic from "+match.RuleSource+" on port "+strconv.Itoa(match.Port)+" via "+match.SecurityGroupID+".",
				"Remove internet ingress on "+match.SecurityGroupID+". Database hosts must not be reachable from the internet.",
			)
			return result.sat(ce, "Database isolation violated — database host is directly accessible from the internet.", start)
		}
	}

	return result.unsat("All database hosts are isolated within their VPC — no cross-VPC or internet paths exist.", start)
}

// ProveTransitiveSSH checks whether any non-bastion host can act as an
// SSH relay to reach production (2+ hop: internet/host -> relay -> production
// where relay is not a bastion).
func (g *Graph) ProveTransitiveSSH(port int) (*ProofResult, error) {
	start := time.Now()

	prod := g.ProductionHosts()
	bastions := g.BastionHosts()

	if len(prod) == 0 {
		return nil, vacuousErr("no hosts tagged stave:environment=production — cannot prove transitive SSH")
	}

	result := newBastionProofResult("transitive-ssh", len(prod), len(bastions))

	for _, dst := range prod {
		for _, relay := range g.allHosts() {
			if relay.IsTrusted(dst) {
				continue
			}
			relayMatch := g.Reachability(relay, dst, port)
			if relayMatch == nil {
				continue
			}

			// Relay can reach prod. Check if relay is reachable from the internet.
			if ce := g.findTransitiveInternetBypass(relay, dst, port, relayMatch); ce != nil {
				return result.sat(ce, "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production.", start)
			}

			// Check if any other non-prod, non-bastion host can reach the relay.
			for _, src := range g.allHosts() {
				if src.IsTrusted(relay, dst) {
					continue
				}
				if ce := g.findTransitiveInternalBypass(src, relay, dst, port, relayMatch); ce != nil {
					return result.sat(ce, "Transitive SSH path exists — a non-bastion host can relay SSH to production via an intermediate host.", start)
				}
			}
		}
	}

	return result.unsat("No transitive SSH paths to production exist — no non-bastion relay can bridge to production.", start)
}

func (g *Graph) findTransitiveInternetBypass(relay, dst *Host, port int, relayMatch *RuleMatch) *Counterexample {
	match := g.findInternetRule(relay, port)
	if match == nil || relayMatch == nil {
		return nil
	}
	relayID, dstID := "", ""
	if relay != nil {
		relayID = relay.ID
	}
	if dst != nil {
		dstID = dst.ID
	}
	return newTransitiveCounterexample(
		match.RuleSource,
		"internet",
		"Host "+relayID+" is SSH-accessible from the internet and",
		relay, dst, port, relayMatch,
		"Remove SSH ingress from "+match.RuleSource+" on "+relayID+" or remove its access to production host "+dstID+".",
	)
}

func (g *Graph) findTransitiveInternalBypass(src, relay, dst *Host, port int, relayMatch *RuleMatch) *Counterexample {
	match := g.Reachability(src, relay, port)
	if match == nil || relayMatch == nil {
		return nil
	}
	srcID, relayID, dstID := "", "", ""
	if src != nil {
		srcID = src.ID
	}
	if relay != nil {
		relayID = relay.ID
	}
	if dst != nil {
		dstID = dst.ID
	}
	return newTransitiveCounterexample(
		srcID,
		srcID,
		"Host "+srcID+" can reach "+relayID+", which",
		relay, dst, port, relayMatch,
		"Remove SSH access from "+srcID+" to "+relayID+" or from "+relayID+" to production host "+dstID+".",
	)
}

// RouteBypassesFirewall reports whether the route targets an internet gateway
// directly without traversing a firewall endpoint. Safe on nil receiver.
func (g *Graph) RouteBypassesFirewall(route Route) bool {
	if g == nil {
		return false
	}
	return route.IsInternetGateway() && !g.Firewalls[route.TargetID]
}

// ProveFirewallMandatory checks that all private subnets route internet
// traffic through a Network Firewall endpoint. Returns UNSAT if all
// egress routes through firewall, SAT if a bypass exists.
func (g *Graph) ProveFirewallMandatory() (*ProofResult, error) {
	start := time.Now()

	privateSubnets := g.PrivateSubnets()
	if len(privateSubnets) == 0 {
		return nil, vacuousErr("no subnets tagged stave:subnet-type=private")
	}
	if len(g.Firewalls) == 0 {
		return nil, vacuousErr("no firewall endpoints found — cannot prove firewall routing")
	}

	result := newProofResult("firewall-mandatory", map[string]int{"private_subnets": len(privateSubnets), "firewall_endpoints": len(g.Firewalls)})

	for _, sub := range privateSubnets {
		if !sub.HasRouteTable() {
			return nil, vacuousErr("subnet %s has no route table association — cannot prove firewall routing", sub.ID)
		}
		for _, route := range g.RoutesForSubnet(sub) {
			if !route.IsDefaultRoute() {
				continue
			}
			if g.RouteBypassesFirewall(route) {
				ce := newRouteCounterexample(
					sub, route, "direct-igw",
					"Subnet "+sub.ID+" has a "+route.Destination+" route to IGW "+route.TargetID+" in route table "+sub.RouteTableID+" without passing through a Network Firewall endpoint.",
					"Change the "+route.Destination+" route in "+sub.RouteTableID+" to target a Network Firewall endpoint instead of "+route.TargetID+".",
				)
				return result.sat(ce, "Firewall bypass exists — private subnet routes internet traffic directly to an internet gateway.", start)
			}
		}
	}

	return result.unsat("All private subnets route internet traffic through a Network Firewall endpoint.", start)
}

// routeTargetClass is the sink classification for a default-route target.
type routeTargetClass int

const (
	routeSink    routeTargetClass = iota // definite internet egress (nat, igw, eigw)
	routeGated                           // cannot determine without additional observation
	routeNonSink                         // no internet egress (local)
)

// RouteTarget encapsulates a default-route target's sink classification,
// resolution reason, and target identity.
type RouteTarget struct {
	Class    routeTargetClass
	Reason   string
	TargetID string
}

func (t RouteTarget) IsSink() bool    { return t.Class == routeSink }
func (t RouteTarget) IsGated() bool   { return t.Class == routeGated }
func (t RouteTarget) IsNonSink() bool { return t.Class == routeNonSink }

// ClassifyTarget classifies a default-route target for the
// transitive-egress prover. The default arm is Gated — an unrecognized
// target_type can only ever widen the answer, never hide a path.
func (r Route) ClassifyTarget() RouteTarget {
	switch r.TargetType {
	case "nat", "igw", "eigw":
		return RouteTarget{Class: routeSink, TargetID: r.TargetID}
	case "local":
		return RouteTarget{Class: routeNonSink, TargetID: r.TargetID}
	case "tgw":
		return RouteTarget{Class: routeGated, Reason: "TGW route table not resolved", TargetID: r.TargetID}
	case "vgw":
		return RouteTarget{Class: routeGated, Reason: "on-premises egress not observable", TargetID: r.TargetID}
	case "vpce":
		return RouteTarget{Class: routeGated, Reason: "firewall policy not evaluated", TargetID: r.TargetID}
	case "instance", "eni":
		return RouteTarget{Class: routeGated, Reason: "NAT instance or appliance forwarding not observable", TargetID: r.TargetID}
	default:
		return RouteTarget{Class: routeGated, Reason: "unrecognized route target", TargetID: r.TargetID}
	}
}

// ProveTransitiveEgress checks that no isolated workload can transitively
// reach the internet via an intermediate host whose subnet has a default
// egress route. Returns UNSAT if no transitive path exists, SAT with a
// counterexample if a path to a definite internet sink exists, or
// EVIDENCE_GATED if a path reaches a route target the snapshot cannot
// resolve.
//
// Verdict order: SAT > EVIDENCE_GATED > UNSAT.
//
// Sound over security-group ingress reachability. NACL denies and
// security-group egress rules are not evaluated, so a SAT counterexample
// may be blocked in practice, but UNSAT does not depend on them.
// Network-layer only — IAM-layer service paths (Lambda invoke, SSM,
// S3 replication, VPC endpoints to request-making services) are not
// evaluated. Single-region snapshot; run per region.
func (g *Graph) ProveTransitiveEgress() (*ProofResult, error) {
	start := time.Now()

	isolated := g.IsolatedHosts()
	if len(isolated) == 0 {
		return nil, vacuousErr("no hosts tagged stave:network-zone=isolated")
	}

	sinks, gated := g.findEgressCandidates()
	if len(sinks) == 0 && len(gated) == 0 {
		return nil, vacuousErr("no non-isolated hosts in subnets with internet egress routes")
	}

	result := newProofResult("transitive-egress", map[string]int{"isolated_hosts": len(isolated), "sink_hosts": len(sinks), "gated_hosts": len(gated)})

	if iso, s, match := g.findFirstEgressPath(isolated, sinks); match != nil {
		portStr := formatPort(match.Port)
		ce := newSGCounterexample(
			iso.ID, s.host.ID, match.Port, "transitive-egress", match,
			"Isolated host "+iso.ID+" can reach "+s.host.ID+" on port "+portStr+". "+s.host.ID+"'s subnet routes "+s.route.Destination+" to "+s.route.Target()+". Two-hop path: "+iso.ID+" → "+s.host.ID+" → internet.",
			"Remove network access from "+iso.ID+" to "+s.host.ID+", or remove "+s.host.ID+"'s internet egress route.",
		)
		return result.sat(ce, "Transitive internet egress path exists — an isolated workload can reach a host with internet egress.", start)
	}

	if iso, gc, match := g.findFirstEgressPath(isolated, gated); match != nil {
		portStr := formatPort(match.Port)
		ce := newSGCounterexample(
			iso.ID, gc.host.ID, match.Port, "gated-egress", match,
			"Isolated host "+iso.ID+" can reach "+gc.host.ID+" on port "+portStr+". "+gc.host.ID+"'s subnet routes "+gc.route.Destination+" to "+gc.route.Target()+" ("+gc.target.Reason+").",
			"Provide observation for "+gc.route.TargetType+" "+gc.target.TargetID+" to settle the verdict, or remove network access from "+iso.ID+" to "+gc.host.ID+".",
		)
		return result.gated(ce, "A path reaches a route target the snapshot cannot resolve. The verdict depends on an observation not yet available.", start)
	}

	return result.unsat("No isolated workload reaches the internet through an intermediate host, over security-group ingress reachability. Sound under that model: NACL denies and security-group egress rules are not evaluated, so a SAT counterexample may be blocked in practice, but UNSAT does not depend on them. Network-layer only — IAM-layer service paths (Lambda invoke, SSM, S3 replication, VPC endpoints to request-making services) are not evaluated. Single-region snapshot; run per region.", start)
}

func formatPort(port int) string {
	if port == 0 {
		return "all"
	}
	return strconv.Itoa(port)
}

func (g *Graph) findFirstEgressPath(isolated []*Host, candidates []egressCandidate) (*Host, egressCandidate, *RuleMatch) {
	if g == nil {
		return nil, egressCandidate{}, nil
	}
	for _, iso := range isolated {
		for _, c := range candidates {
			if match := g.ReachabilityAnyPort(iso, c.host); match != nil {
				return iso, c, match
			}
		}
	}
	return nil, egressCandidate{}, nil
}

type egressCandidate struct {
	host   *Host
	route  Route
	target RouteTarget
}

// findEgressCandidates identifies all non-isolated hosts with default routes,
// partitioned into sink candidates (definite egress) and gated candidates (observable-dependent).
func (g *Graph) findEgressCandidates() (sinks []egressCandidate, gated []egressCandidate) {
	for _, h := range g.allHosts() {
		if h.IsIsolated() {
			continue
		}
		sub := g.SubnetForHost(h)
		if !sub.HasRouteTable() {
			continue
		}
		for _, route := range g.RoutesForSubnet(sub) {
			if !route.IsDefaultRoute() {
				continue
			}
			target := route.ClassifyTarget()
			if target.IsNonSink() {
				continue
			}
			c := egressCandidate{
				host:   h,
				route:  route,
				target: target,
			}
			if target.IsSink() {
				sinks = append(sinks, c)
			} else if target.IsGated() {
				gated = append(gated, c)
			}
			break
		}
	}
	return sinks, gated
}
