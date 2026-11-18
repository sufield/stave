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
		Source:      sub.SafeID(),
		Destination: route.TargetID,
		PathType:    pathType,
		Explanation: explanation,
		Remediation: remediation,
	}
	if sub != nil {
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
	relayID, dstID := relay.SafeID(), dst.SafeID()
	explanation := fmt.Sprintf("%s can reach production host %s on port %d. Two-hop path: %s -> %s -> %s.",
		hop1Lead, dstID, port, hop1Path, relayID, dstID)
	return newSGCounterexample(
		fmt.Sprintf("%s -> %s", hop1ID, relayID), dstID, port, "transitive", relayMatch,
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

// Prove runs the proof for the specified safety property on the network graph.
// Supported properties: bastion-ssh, prod-dev-isolation, database-isolation,
// firewall-mandatory, transitive-ssh, transitive-egress.
func (g *Graph) Prove(property string, port int) (*ProofResult, error) {
	if g == nil {
		return nil, errors.New("network graph is nil")
	}
	if port == 0 {
		port = 22
	}
	switch property {
	case "bastion-ssh", "":
		return g.ProveBastionSSH(port)
	case "prod-dev-isolation":
		return g.ProveProdDevIsolation()
	case "database-isolation":
		return g.ProveDatabaseIsolation()
	case "firewall-mandatory":
		return g.ProveFirewallMandatory()
	case "transitive-ssh":
		return g.ProveTransitiveSSH(port)
	case "transitive-egress":
		return g.ProveTransitiveEgress()
	default:
		return nil, fmt.Errorf("unknown property %q (valid: bastion-ssh, prod-dev-isolation, database-isolation, firewall-mandatory, transitive-ssh, transitive-egress)", property)
	}
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
		if ce, reason := g.findHostBastionBypass(dst, port, bastions); ce != nil {
			result.SSHPaths++
			return result.sat(ce, reason, start)
		}
	}

	return result.unsat("All SSH paths to production traverse a bastion host.", start)
}

func (g *Graph) findInternalBastionSSHBypass(src, dst *Host, port int, bastions []*Host) (*Counterexample, string) {
	if g == nil || src == nil || dst == nil || src.IsTrusted(dst) {
		return nil, ""
	}
	match := g.Reachability(src, dst, port)
	if match == nil {
		return nil, ""
	}
	ce := newInternalBastionBypassCounterexample(src, dst, port, match, bastions)
	return ce, "Bastion bypass exists — a non-bastion host can SSH to production without traversing a bastion."
}

// newInternalBastionBypassCounterexample constructs a Counterexample for an internal SSH bastion bypass violation.
// Safe on nil src, dst, or match.
func newInternalBastionBypassCounterexample(src, dst *Host, port int, match *RuleMatch, bastions []*Host) *Counterexample {
	if src == nil || dst == nil || match == nil {
		return nil
	}
	return newSGCounterexample(
		src.ID, dst.ID, port, match.PathType, match,
		match.Explanation(src, dst),
		match.Remediation(bastions),
	)
}

func (g *Graph) findHostBastionBypass(dst *Host, port int, bastions []*Host) (*Counterexample, string) {
	if g == nil || dst == nil {
		return nil, ""
	}
	// Check internal SSH ingress from non-bastion, non-production sources.
	for _, src := range g.allHosts() {
		if ce, reason := g.findInternalBastionSSHBypass(src, dst, port, bastions); ce != nil {
			return ce, reason
		}
	}

	// Check external entry (0.0.0.0/0).
	if ce := g.findExternalBypass(dst, port); ce != nil {
		return ce, "Bastion bypass exists — production host is directly SSH-accessible from the internet."
	}

	return nil, ""
}

func (g *Graph) findExternalBypass(dst *Host, port int) *Counterexample {
	match := g.findInternetRule(dst, port)
	if match == nil {
		return nil
	}
	return newExternalBypassCounterexample(dst, port, match)
}

// newExternalBypassCounterexample constructs a Counterexample for an external internet-facing bastion bypass violation.
// Safe on nil dst or match.
func newExternalBypassCounterexample(dst *Host, port int, match *RuleMatch) *Counterexample {
	if dst == nil || match == nil {
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

	if src, dst, match := g.findCrossEnvBypass(prod, dev); match != nil {
		ce := newCrossEnvBypassCounterexample(src, dst, match)
		return result.sat(ce, "Production-development isolation violated — a cross-environment path exists.", start)
	}

	return result.unsat("Production and development environments are network-isolated.", start)
}

// newCrossEnvBypassCounterexample constructs a Counterexample for a cross-environment reachability violation.
// Safe on nil src, dst, or match.
func newCrossEnvBypassCounterexample(src, dst *Host, match *RuleMatch) *Counterexample {
	if src == nil || dst == nil || match == nil {
		return nil
	}
	return newSGCounterexample(
		src.ID, dst.ID, match.Port, match.PathType, match,
		fmt.Sprintf("Host %s (%s) can reach %s (%s) via %s.", src.ID, src.Environment(), dst.ID, dst.Environment(), match.PathType),
		fmt.Sprintf("Remove cross-environment ingress rule on %s. Ensure production and development VPCs have no peering or broad CIDR rules.", match.SecurityGroupID),
	)
}

// findAnyReachabilityPath searches for the first reachability rule match between any
// source host and destination host on any port. Safe on nil receiver or nil slices.
func (g *Graph) findAnyReachabilityPath(sources, destinations []*Host) (*Host, *Host, *RuleMatch) {
	if g == nil {
		return nil, nil, nil
	}
	for _, src := range sources {
		for _, dst := range destinations {
			if match := g.ReachabilityAnyPort(src, dst); match != nil {
				return src, dst, match
			}
		}
	}
	return nil, nil, nil
}

func (g *Graph) findCrossEnvBypass(prod, dev []*Host) (*Host, *Host, *RuleMatch) {
	if g == nil {
		return nil, nil, nil
	}
	if src, dst, match := g.findAnyReachabilityPath(prod, dev); match != nil {
		return src, dst, match
	}
	return g.findAnyReachabilityPath(dev, prod)
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
		if ce, reason := g.findDatabaseBypass(dst); ce != nil {
			return result.sat(ce, reason, start)
		}
	}

	return result.unsat("All database hosts are isolated within their VPC — no cross-VPC or internet paths exist.", start)
}

// newCrossVPCDatabaseBypassCounterexample constructs a Counterexample for a cross-VPC database reachability violation.
// Safe on nil src, dst, or match.
func newCrossVPCDatabaseBypassCounterexample(src, dst *Host, match *RuleMatch) *Counterexample {
	if src == nil || dst == nil || match == nil {
		return nil
	}
	return newSGCounterexample(
		src.ID, dst.ID, match.Port, match.PathType, match,
		fmt.Sprintf("Host %s (vpc:%s) can reach database host %s (vpc:%s) via %s.", src.ID, src.VPCID, dst.ID, dst.VPCID, match.PathType),
		fmt.Sprintf("Remove cross-VPC ingress to database SG %s. Restrict to application-tier SG references within the same VPC.", match.SecurityGroupID),
	)
}

// newInternetDatabaseBypassCounterexample constructs a Counterexample for an internet database reachability violation.
// Safe on nil dst or match.
func newInternetDatabaseBypassCounterexample(dst *Host, match *RuleMatch) *Counterexample {
	if dst == nil || match == nil {
		return nil
	}
	return newSGCounterexample(
		match.RuleSource+" (internet)", dst.ID, match.Port, match.PathType, match,
		fmt.Sprintf("Database host %s accepts traffic from %s on port %d via %s.", dst.ID, match.RuleSource, match.Port, match.SecurityGroupID),
		fmt.Sprintf("Remove internet ingress on %s. Database hosts must not be reachable from the internet.", match.SecurityGroupID),
	)
}

func (g *Graph) findCrossVPCHostBypass(src, dst *Host) (*Counterexample, string) {
	if g == nil || src == nil || dst == nil || src.IsInternal(dst) {
		return nil, ""
	}
	match := g.ReachabilityAnyPort(src, dst)
	if match == nil {
		return nil, ""
	}
	ce := newCrossVPCDatabaseBypassCounterexample(src, dst, match)
	return ce, "Database isolation violated — a host outside the database VPC can reach a database host."
}

func (g *Graph) findCrossVPCDatabaseBypass(dst *Host) (*Counterexample, string) {
	if g == nil || dst == nil {
		return nil, ""
	}
	for _, src := range g.allHosts() {
		if ce, reason := g.findCrossVPCHostBypass(src, dst); ce != nil {
			return ce, reason
		}
	}
	return nil, ""
}

func (g *Graph) findInternetDatabaseBypass(dst *Host) (*Counterexample, string) {
	if g == nil || dst == nil {
		return nil, ""
	}
	if match := g.findInternetRuleAnyPort(dst); match != nil {
		ce := newInternetDatabaseBypassCounterexample(dst, match)

		return ce, "Database isolation violated — database host is directly accessible from the internet."
	}
	return nil, ""
}

func (g *Graph) findDatabaseBypass(dst *Host) (*Counterexample, string) {
	if g == nil || dst == nil {
		return nil, ""
	}
	if ce, reason := g.findCrossVPCDatabaseBypass(dst); ce != nil {
		return ce, reason
	}
	return g.findInternetDatabaseBypass(dst)
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
		if ce, reason := g.findHostTransitiveSSHBypass(dst, port); ce != nil {
			return result.sat(ce, reason, start)
		}
	}

	return result.unsat("No transitive SSH paths to production exist — no non-bastion relay can bridge to production.", start)
}

func (g *Graph) findRelayCandidateTransitiveSSHBypass(relay, dst *Host, port int) (*Counterexample, string) {
	if g == nil || relay == nil || dst == nil || relay.IsTrusted(dst) {
		return nil, ""
	}
	relayMatch := g.Reachability(relay, dst, port)
	if relayMatch == nil {
		return nil, ""
	}
	return g.findRelayTransitiveSSHBypass(relay, dst, port, relayMatch)
}

func (g *Graph) findHostTransitiveSSHBypass(dst *Host, port int) (*Counterexample, string) {
	if g == nil || dst == nil {
		return nil, ""
	}
	for _, relay := range g.allHosts() {
		if ce, reason := g.findRelayCandidateTransitiveSSHBypass(relay, dst, port); ce != nil {
			return ce, reason
		}
	}
	return nil, ""
}

func (g *Graph) findRelayTransitiveSSHBypass(relay, dst *Host, port int, relayMatch *RuleMatch) (*Counterexample, string) {
	if g == nil || relay == nil || dst == nil || relayMatch == nil {
		return nil, ""
	}
	if ce := g.findTransitiveInternetBypass(relay, dst, port, relayMatch); ce != nil {
		return ce, "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production."
	}
	if ce := g.findTransitiveInternalHostBypass(relay, dst, port, relayMatch); ce != nil {
		return ce, "Transitive SSH path exists — a non-bastion host can relay SSH to production via an intermediate host."
	}
	return nil, ""
}

func (g *Graph) findTransitiveInternalHostBypass(relay, dst *Host, port int, relayMatch *RuleMatch) *Counterexample {
	if g == nil || relay == nil || dst == nil || relayMatch == nil {
		return nil
	}
	for _, src := range g.allHosts() {
		if src.IsTrusted(relay, dst) {
			continue
		}
		if ce := g.findTransitiveInternalBypass(src, relay, dst, port, relayMatch); ce != nil {
			return ce
		}
	}
	return nil
}

func (g *Graph) findTransitiveInternetBypass(relay, dst *Host, port int, relayMatch *RuleMatch) *Counterexample {
	match := g.findInternetRule(relay, port)
	if match == nil || relayMatch == nil {
		return nil
	}
	relayID, dstID := relay.SafeID(), dst.SafeID()
	return newTransitiveCounterexample(
		match.RuleSource,
		"internet",
		fmt.Sprintf("Host %s is SSH-accessible from the internet and", relayID),
		relay, dst, port, relayMatch,
		fmt.Sprintf("Remove SSH ingress from %s on %s or remove its access to production host %s.", match.RuleSource, relayID, dstID),
	)
}

func (g *Graph) findTransitiveInternalBypass(src, relay, dst *Host, port int, relayMatch *RuleMatch) *Counterexample {
	match := g.Reachability(src, relay, port)
	if match == nil || relayMatch == nil {
		return nil
	}
	srcID, relayID, dstID := src.SafeID(), relay.SafeID(), dst.SafeID()
	return newTransitiveCounterexample(
		srcID,
		srcID,
		fmt.Sprintf("Host %s can reach %s, which", srcID, relayID),
		relay, dst, port, relayMatch,
		fmt.Sprintf("Remove SSH access from %s to %s or from %s to production host %s.", srcID, relayID, relayID, dstID),
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
		if ce := g.findSubnetFirewallBypass(sub); ce != nil {
			return result.sat(ce, "Firewall bypass exists — private subnet routes internet traffic directly to an internet gateway.", start)
		}
	}

	return result.unsat("All private subnets route internet traffic through a Network Firewall endpoint.", start)
}

func (g *Graph) findSubnetBypassingRoute(sub *Subnet) (Route, bool) {
	route, ok := g.DefaultRouteForSubnet(sub)
	if ok && g.RouteBypassesFirewall(route) {
		return route, true
	}
	return Route{}, false
}

// newFirewallBypassCounterexample constructs a Counterexample for a direct-to-IGW firewall bypass.
// Safe on nil sub.
func newFirewallBypassCounterexample(sub *Subnet, route Route) *Counterexample {
	if sub == nil {
		return nil
	}
	return newRouteCounterexample(
		sub, route, "direct-igw",
		fmt.Sprintf("Subnet %s has a %s route to IGW %s in route table %s without passing through a Network Firewall endpoint.", sub.ID, route.Destination, route.TargetID, sub.RouteTableID),
		fmt.Sprintf("Change the %s route in %s to target a Network Firewall endpoint instead of %s.", route.Destination, sub.RouteTableID, route.TargetID),
	)
}

func (g *Graph) findSubnetFirewallBypass(sub *Subnet) *Counterexample {
	route, ok := g.findSubnetBypassingRoute(sub)
	if !ok {
		return nil
	}
	return newFirewallBypassCounterexample(sub, route)
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

	candidates := g.findEgressCandidates()
	if candidates.IsEmpty() {
		return nil, vacuousErr("no non-isolated hosts in subnets with internet egress routes")
	}

	result := newProofResult("transitive-egress", map[string]int{"isolated_hosts": len(isolated), "sink_hosts": len(candidates.sinks), "gated_hosts": len(candidates.gated)})

	if ce := g.findTransitiveEgressBypass(isolated, candidates.sinks); ce != nil {
		return result.sat(ce, "Transitive internet egress path exists — an isolated workload can reach a host with internet egress.", start)
	}

	if ce := g.findTransitiveEgressGated(isolated, candidates.gated); ce != nil {
		return result.gated(ce, "A path reaches a route target the snapshot cannot resolve. The verdict depends on an observation not yet available.", start)
	}

	return result.unsat("No isolated workload reaches the internet through an intermediate host, over security-group ingress reachability. Sound under that model: NACL denies and security-group egress rules are not evaluated, so a SAT counterexample may be blocked in practice, but UNSAT does not depend on them. Network-layer only — IAM-layer service paths (Lambda invoke, SSM, S3 replication, VPC endpoints to request-making services) are not evaluated. Single-region snapshot; run per region.", start)
}

func newEgressBypassCounterexample(iso *Host, s egressCandidate, match *RuleMatch) *Counterexample {
	if iso == nil || s.host == nil || match == nil {
		return nil
	}
	portStr := FormatPort(match.Port)
	return newSGCounterexample(
		iso.ID, s.host.ID, match.Port, "transitive-egress", match,
		fmt.Sprintf("Isolated host %s can reach %s on port %s. %s's subnet routes %s to %s. Two-hop path: %s → %s → internet.",
			iso.ID, s.host.ID, portStr, s.host.ID, s.route.Destination, s.route.Target(), iso.ID, s.host.ID),
		fmt.Sprintf("Remove network access from %s to %s, or remove %s's internet egress route.",
			iso.ID, s.host.ID, s.host.ID),
	)
}

func newEgressGatedCounterexample(iso *Host, gc egressCandidate, match *RuleMatch) *Counterexample {
	if iso == nil || gc.host == nil || match == nil {
		return nil
	}
	portStr := FormatPort(match.Port)
	return newSGCounterexample(
		iso.ID, gc.host.ID, match.Port, "gated-egress", match,
		fmt.Sprintf("Isolated host %s can reach %s on port %s. %s's subnet routes %s to %s (%s).",
			iso.ID, gc.host.ID, portStr, gc.host.ID, gc.route.Destination, gc.route.Target(), gc.target.Reason),
		fmt.Sprintf("Provide observation for %s %s to settle the verdict, or remove network access from %s to %s.",
			gc.route.TargetType, gc.target.TargetID, iso.ID, gc.host.ID),
	)
}

func (g *Graph) findTransitiveEgressBypass(isolated []*Host, sinks []egressCandidate) *Counterexample {
	iso, s, match := g.findFirstEgressPath(isolated, sinks)
	if match == nil {
		return nil
	}
	return newEgressBypassCounterexample(iso, s, match)
}

func (g *Graph) findTransitiveEgressGated(isolated []*Host, gated []egressCandidate) *Counterexample {
	iso, gc, match := g.findFirstEgressPath(isolated, gated)
	if match == nil {
		return nil
	}
	return newEgressGatedCounterexample(iso, gc, match)
}

// FormatPort formats a network port number. Returns "all" if port is 0.
func FormatPort(port int) string {
	if port == 0 {
		return "all"
	}
	return strconv.Itoa(port)
}

// findHostEgressCandidatePath checks if an isolated host can reach any egress candidate host,
// returning the candidate, rule match, and true if a path is found. Safe on nil receiver or nil host.
func (g *Graph) findHostEgressCandidatePath(iso *Host, candidates []egressCandidate) (egressCandidate, *RuleMatch, bool) {
	if g == nil || iso == nil {
		return egressCandidate{}, nil, false
	}
	for _, c := range candidates {
		if match := g.ReachabilityAnyPort(iso, c.host); match != nil {
			return c, match, true
		}
	}
	return egressCandidate{}, nil, false
}

func (g *Graph) findFirstEgressPath(isolated []*Host, candidates []egressCandidate) (*Host, egressCandidate, *RuleMatch) {
	if g == nil {
		return nil, egressCandidate{}, nil
	}
	for _, iso := range isolated {
		if c, match, ok := g.findHostEgressCandidatePath(iso, candidates); ok {
			return iso, c, match
		}
	}
	return nil, egressCandidate{}, nil
}

type egressCandidate struct {
	host   *Host
	route  Route
	target RouteTarget
}

// newEgressCandidate constructs an egressCandidate for a host, route, and target classification.
func newEgressCandidate(h *Host, route Route, target RouteTarget) egressCandidate {
	return egressCandidate{
		host:   h,
		route:  route,
		target: target,
	}
}

// hostEgressCandidate determines if a host has an egress candidate default route.
// Returns false if the host is nil, isolated, lacks a route table, or has no non-local default route.
func (g *Graph) hostEgressCandidate(h *Host) (egressCandidate, bool) {
	if g == nil || h == nil || h.IsIsolated() {
		return egressCandidate{}, false
	}
	sub := g.SubnetForHost(h)
	route, ok := g.DefaultRouteForSubnet(sub)
	if !ok {
		return egressCandidate{}, false
	}
	target := route.ClassifyTarget()
	if target.IsNonSink() {
		return egressCandidate{}, false
	}
	return newEgressCandidate(h, route, target), true
}

// egressCandidatePartition encapsulates non-isolated candidate hosts partitioned
// by their default route target classification into sink and gated candidates.
type egressCandidatePartition struct {
	sinks []egressCandidate
	gated []egressCandidate
}

// IsEmpty reports whether no candidates exist in either partition.
func (p egressCandidatePartition) IsEmpty() bool {
	return len(p.sinks) == 0 && len(p.gated) == 0
}

// findEgressCandidates identifies all non-isolated hosts with default routes,
// partitioned into sink candidates (definite egress) and gated candidates (observable-dependent).
func (g *Graph) findEgressCandidates() egressCandidatePartition {
	if g == nil {
		return egressCandidatePartition{}
	}
	var p egressCandidatePartition
	for _, h := range g.allHosts() {
		c, ok := g.hostEgressCandidate(h)
		if !ok {
			continue
		}
		if c.target.IsSink() {
			p.sinks = append(p.sinks, c)
		} else if c.target.IsGated() {
			p.gated = append(p.gated, c)
		}
	}
	return p
}
