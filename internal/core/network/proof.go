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
	"slices"
	"strconv"
	"strings"
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

const (
	// VerdictUNSAT indicates the proof confirmed that no violation exists.
	VerdictUNSAT = "UNSAT"
	// VerdictSAT indicates the proof found a counterexample violating the property.
	VerdictSAT = "SAT"
	// VerdictEvidenceGated indicates the proof was blocked by unresolved evidence.
	VerdictEvidenceGated = "EVIDENCE_GATED"
)

func (r *ProofResult) finish(result, interpretation string, ce *Counterexample, start time.Time) (*ProofResult, error) {
	r.Result = result
	r.Interpretation = interpretation
	r.Counterexample = ce
	r.SolveTimeMs = time.Since(start).Milliseconds()
	return r, nil
}

func (r *ProofResult) sat(ce *Counterexample, interpretation string, start time.Time) (*ProofResult, error) {
	return r.finish(VerdictSAT, interpretation, ce, start)
}

func (r *ProofResult) unsat(interpretation string, start time.Time) (*ProofResult, error) {
	return r.finish(VerdictUNSAT, interpretation, nil, start)
}

func (r *ProofResult) gated(ce *Counterexample, interpretation string, start time.Time) (*ProofResult, error) {
	return r.finish(VerdictEvidenceGated, interpretation, ce, start)
}

// IsUNSAT reports whether the proof confirmed that no violation exists.
func (r *ProofResult) IsUNSAT() bool {
	return r != nil && r.Result == VerdictUNSAT
}

// IsEvidenceGated reports whether the proof was blocked by unresolved evidence.
func (r *ProofResult) IsEvidenceGated() bool {
	return r != nil && r.Result == VerdictEvidenceGated
}

// ScopeCount returns the number of entries in the scope map, or 0 if nil.
func (r *ProofResult) ScopeCount() int {
	if r == nil {
		return 0
	}
	return len(r.Scope)
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

// IsDirectIGW reports whether the counterexample represents a direct Internet Gateway bypass path.
func (ce *Counterexample) IsDirectIGW() bool {
	return ce != nil && ce.PathType == PathTypeDirectIGW
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
			RouteTableID: sub.SafeRouteTableID(),
			Destination:  route.Destination,
		}
	}
	return ce
}

// formatTransitivePathSource formats the composite source string for a two-hop path (e.g. "hop1 -> relay").
func formatTransitivePathSource(hop1ID, relayID string) string {
	return fmt.Sprintf("%s -> %s", hop1ID, relayID)
}

// formatTransitiveExplanation formats the explanation for a two-hop transitive path violation.
func formatTransitiveExplanation(hop1Lead, dstID, hop1Path, relayID string, port int) string {
	return fmt.Sprintf("%s can reach production host %s on port %d. Two-hop path: %s -> %s -> %s.",
		hop1Lead, dstID, port, hop1Path, relayID, dstID)
}

// newTransitiveCounterexample constructs a Counterexample for a two-hop transitive path violation
// (hop1 -> relay -> dst), formatting the explanation and remediation consistently.
func newTransitiveCounterexample(hop1ID, hop1Path, hop1Lead string, relay, dst *Host, port int, relayMatch *RuleMatch, remediation string) *Counterexample {
	relayID, dstID := relay.SafeID(), dst.SafeID()
	explanation := formatTransitiveExplanation(hop1Lead, dstID, hop1Path, relayID, port)
	source := formatTransitivePathSource(hop1ID, relayID)
	return newSGCounterexample(
		source, dstID, port, PathTypeTransitive, relayMatch,
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

// FormatEntry formats an enumerated SSH path line with a 1-based index prefix.
func (p SSHPath) FormatEntry(index int) string {
	return fmt.Sprintf("  %d. %s → %s  [%s]  sg:%s  via:%s",
		index, p.Source, p.Destination, p.PathType, p.RuleSG, p.RuleSource)
}

// EnumerateResult is the output of SSH entry point enumeration.
type EnumerateResult struct {
	Scope           string    `json:"scope"`
	Port            int       `json:"port"`
	ProductionHosts int       `json:"production_hosts"`
	Paths           []SSHPath `json:"paths"`
}

// NewEnumerateResult constructs an EnumerateResult for SSH entry point enumeration.
func NewEnumerateResult(scope string, port, prodHosts int, paths []SSHPath) *EnumerateResult {
	return &EnumerateResult{
		Scope:           scope,
		Port:            port,
		ProductionHosts: prodHosts,
		Paths:           paths,
	}
}

// PathCount returns the number of enumerated SSH paths, or 0 if receiver is nil.
func (r *EnumerateResult) PathCount() int {
	if r == nil {
		return 0
	}
	return len(r.Paths)
}

// HasPaths reports whether any SSH paths were found.
func (r *EnumerateResult) HasPaths() bool {
	return r.PathCount() > 0
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

// PropertyBastionSSH is the safety property name for bastion SSH routing proofs.
const PropertyBastionSSH = "bastion-ssh"

// PropertyProdDevIsolation is the safety property name for production-development isolation proofs.
const PropertyProdDevIsolation = "prod-dev-isolation"

// PropertyDatabaseIsolation is the safety property name for database tier isolation proofs.
const PropertyDatabaseIsolation = "database-isolation"

// PropertyFirewallMandatory is the safety property name for mandatory firewall routing proofs.
const PropertyFirewallMandatory = "firewall-mandatory"

// PropertyTransitiveSSH is the safety property name for transitive SSH routing proofs.
const PropertyTransitiveSSH = "transitive-ssh"

// PropertyTransitiveEgress is the safety property name for transitive internet egress proofs.
const PropertyTransitiveEgress = "transitive-egress"

// DefaultSSHPort is the default port used when verifying SSH reachability and safety properties.
const DefaultSSHPort = 22

// SupportedProperties lists all safety properties supported by the network graph prover.
var SupportedProperties = []string{
	PropertyBastionSSH,
	PropertyProdDevIsolation,
	PropertyDatabaseIsolation,
	PropertyFirewallMandatory,
	PropertyTransitiveSSH,
	PropertyTransitiveEgress,
}

// IsSupportedProperty reports whether prop is one of the supported safety properties.
func IsSupportedProperty(prop string) bool {
	return slices.Contains(SupportedProperties, prop)
}

// SupportedPropertiesList returns a comma-separated list of supported safety properties.
func SupportedPropertiesList() string {
	return strings.Join(SupportedProperties, ", ")
}

// Prove runs the proof for the specified safety property on the network graph.
// Supported properties: bastion-ssh, prod-dev-isolation, database-isolation,
// firewall-mandatory, transitive-ssh, transitive-egress.
func (g *Graph) Prove(property string, port int) (*ProofResult, error) {
	if g == nil {
		return nil, errors.New("network graph is nil")
	}
	if port == 0 {
		port = DefaultSSHPort
	}
	switch property {
	case PropertyBastionSSH, "":
		return g.ProveBastionSSH(port)
	case PropertyProdDevIsolation:
		return g.ProveProdDevIsolation()
	case PropertyDatabaseIsolation:
		return g.ProveDatabaseIsolation()
	case PropertyFirewallMandatory:
		return g.ProveFirewallMandatory()
	case PropertyTransitiveSSH:
		return g.ProveTransitiveSSH(port)
	case PropertyTransitiveEgress:
		return g.ProveTransitiveEgress()
	default:
		return nil, fmt.Errorf("unknown property %q (valid: %s)", property, SupportedPropertiesList())
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

	result := newBastionProofResult(PropertyBastionSSH, len(prod), len(bastions))

	// Find all SSH paths to production from non-bastion, non-production sources.
	for _, dst := range prod {
		if ce, reason := g.findHostBastionBypass(dst, port, bastions); ce != nil {
			result.SSHPaths++
			return result.sat(ce, reason, start)
		}
	}

	return result.unsat(InterpretationBastionUNSAT, start)
}

const (
	// InterpretationBastionUNSAT is the sound UNSAT interpretation returned when all SSH paths to production traverse a bastion.
	InterpretationBastionUNSAT = "All SSH paths to production traverse a bastion host."
	// ReasonInternalBastionBypass is the explanation returned when a non-bastion host can directly SSH to production.
	ReasonInternalBastionBypass = "Bastion bypass exists — a non-bastion host can SSH to production without traversing a bastion." //nolint:gosec // G101 false positive: explanation message, not a credential
	// ReasonExternalBastionBypass is the explanation returned when a production host is directly accessible from the internet.
	ReasonExternalBastionBypass = "Bastion bypass exists — production host is directly SSH-accessible from the internet." //nolint:gosec // G101 false positive: explanation message, not a credential
)

func (g *Graph) findInternalBastionSSHBypass(src, dst *Host, port int, bastions []*Host) (*Counterexample, string) {
	if g == nil || src == nil || dst == nil || src.IsTrusted(dst) {
		return nil, ""
	}
	match := g.Reachability(src, dst, port)
	if match == nil {
		return nil, ""
	}
	ce := newInternalBastionBypassCounterexample(src, dst, port, match, bastions)
	return ce, ReasonInternalBastionBypass
}

// newInternalBastionBypassCounterexample constructs a Counterexample for an internal SSH bastion bypass violation.
// Safe on nil src, dst, or match.
func newInternalBastionBypassCounterexample(src, dst *Host, port int, match *RuleMatch, bastions []*Host) *Counterexample {
	if src == nil || dst == nil || match == nil {
		return nil
	}
	return newSGCounterexample(
		src.SafeID(), dst.SafeID(), port, match.PathType, match,
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
		return ce, ReasonExternalBastionBypass
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
		match.InternetSource(), dst.SafeID(), port, match.PathType, match,
		match.Explanation(nil, dst),
		match.Remediation(nil),
	)
}

const (
	// ReasonProdDevViolation is the explanation returned when a cross-environment network path exists.
	ReasonProdDevViolation = "Production-development isolation violated — a cross-environment path exists."
	// InterpretationProdDevIsolated is the interpretation returned when production and development are isolated.
	InterpretationProdDevIsolated = "Production and development environments are network-isolated."
)

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

	result := newProofResult(PropertyProdDevIsolation, map[string]int{"production_hosts": len(prod), "development_hosts": len(dev)})

	if src, dst, match := g.findCrossEnvBypass(prod, dev); match != nil {
		ce := newCrossEnvBypassCounterexample(src, dst, match)
		return result.sat(ce, ReasonProdDevViolation, start)
	}

	return result.unsat(InterpretationProdDevIsolated, start)
}

// formatCrossEnvExplanation formats the explanation for a cross-environment reachability violation.
func formatCrossEnvExplanation(srcID, srcEnv, dstID, dstEnv, pathType string) string {
	return fmt.Sprintf("Host %s (%s) can reach %s (%s) via %s.", srcID, srcEnv, dstID, dstEnv, pathType)
}

// formatCrossEnvRemediation formats the remediation advice for a cross-environment reachability violation.
func formatCrossEnvRemediation(sgID string) string {
	return fmt.Sprintf("Remove cross-environment ingress rule on %s. Ensure production and development VPCs have no peering or broad CIDR rules.", sgID)
}

// newCrossEnvBypassCounterexample constructs a Counterexample for a cross-environment reachability violation.
// Safe on nil src, dst, or match.
func newCrossEnvBypassCounterexample(src, dst *Host, match *RuleMatch) *Counterexample {
	if src == nil || dst == nil || match == nil {
		return nil
	}
	srcID, dstID := src.SafeID(), dst.SafeID()
	return newSGCounterexample(
		srcID, dstID, match.Port, match.PathType, match,
		formatCrossEnvExplanation(srcID, src.Environment(), dstID, dst.Environment(), match.PathType),
		formatCrossEnvRemediation(match.SecurityGroupID),
	)
}

// ReachabilityPath searches for the first authorized reachability match from sources
// to destinations on the specified port. If port is 0, any port is matched.
// Safe on nil receiver or nil slices.
func (g *Graph) ReachabilityPath(sources, destinations []*Host, port int) (*Host, *Host, *RuleMatch) {
	if g == nil {
		return nil, nil, nil
	}
	for _, src := range sources {
		for _, dst := range destinations {
			var match *RuleMatch
			if port == 0 {
				match = g.ReachabilityAnyPort(src, dst)
			} else {
				match = g.Reachability(src, dst, port)
			}
			if match != nil {
				return src, dst, match
			}
		}
	}
	return nil, nil, nil
}

// findAnyReachabilityPath searches for the first reachability rule match between any
// source host and destination host on any port. Safe on nil receiver or nil slices.
func (g *Graph) findAnyReachabilityPath(sources, destinations []*Host) (*Host, *Host, *RuleMatch) {
	return g.ReachabilityPath(sources, destinations, 0)
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

const (
	// InterpretationDatabaseIsolated is the interpretation returned when all database hosts are isolated within their VPC.
	InterpretationDatabaseIsolated = "All database hosts are isolated within their VPC — no cross-VPC or internet paths exist."
	// ReasonCrossVPCDatabaseBypass is the explanation returned when a host outside the database VPC can reach a database host.
	ReasonCrossVPCDatabaseBypass = "Database isolation violated — a host outside the database VPC can reach a database host." //nolint:gosec // G101 false positive: explanation message, not a credential
	// ReasonInternetDatabaseBypass is the explanation returned when a database host is accessible from the internet.
	ReasonInternetDatabaseBypass = "Database isolation violated — database host is directly accessible from the internet." //nolint:gosec // G101 false positive: explanation message, not a credential
)

// ProveDatabaseIsolation checks that no host outside the database VPC
// can reach a database-tier host. Returns UNSAT if isolation holds,
// SAT with a counterexample if an external path exists.
func (g *Graph) ProveDatabaseIsolation() (*ProofResult, error) {
	start := time.Now()

	dbHosts := g.DatabaseHosts()
	if len(dbHosts) == 0 {
		return nil, vacuousErr("no hosts tagged stave:tier=database")
	}

	result := newProofResult(PropertyDatabaseIsolation, map[string]int{"database_hosts": len(dbHosts)})

	if ce, reason := g.findDatabaseTierBypass(dbHosts); ce != nil {
		return result.sat(ce, reason, start)
	}

	return result.unsat(InterpretationDatabaseIsolated, start)
}

func (g *Graph) findDatabaseTierBypass(dbHosts []*Host) (*Counterexample, string) {
	for _, dst := range dbHosts {
		if ce, reason := g.findDatabaseBypass(dst); ce != nil {
			return ce, reason
		}
	}
	return nil, ""
}

// formatCrossVPCDatabaseExplanation formats the explanation for a cross-VPC database reachability violation.
func formatCrossVPCDatabaseExplanation(srcID, srcVPC, dstID, dstVPC, pathType string) string {
	return fmt.Sprintf("Host %s (vpc:%s) can reach database host %s (vpc:%s) via %s.", srcID, srcVPC, dstID, dstVPC, pathType)
}

// formatCrossVPCDatabaseRemediation formats the remediation advice for a cross-VPC database reachability violation.
func formatCrossVPCDatabaseRemediation(sgID string) string {
	return fmt.Sprintf("Remove cross-VPC ingress to database SG %s. Restrict to application-tier SG references within the same VPC.", sgID)
}

// newCrossVPCDatabaseBypassCounterexample constructs a Counterexample for a cross-VPC database reachability violation.
// Safe on nil src, dst, or match.
func newCrossVPCDatabaseBypassCounterexample(src, dst *Host, match *RuleMatch) *Counterexample {
	if src == nil || dst == nil || match == nil {
		return nil
	}
	srcID, srcVPC := src.SafeID(), src.SafeVPCID()
	dstID, dstVPC := dst.SafeID(), dst.SafeVPCID()
	return newSGCounterexample(
		srcID, dstID, match.Port, match.PathType, match,
		formatCrossVPCDatabaseExplanation(srcID, srcVPC, dstID, dstVPC, match.PathType),
		formatCrossVPCDatabaseRemediation(match.SecurityGroupID),
	)
}

// formatInternetDatabaseExplanation formats the explanation for an internet database reachability violation.
func formatInternetDatabaseExplanation(dstID, ruleSource string, port int, sgID string) string {
	return fmt.Sprintf("Database host %s accepts traffic from %s on port %d via %s.", dstID, ruleSource, port, sgID)
}

// formatInternetDatabaseRemediation formats the remediation advice for an internet database reachability violation.
func formatInternetDatabaseRemediation(sgID string) string {
	return fmt.Sprintf("Remove internet ingress on %s. Database hosts must not be reachable from the internet.", sgID)
}

// newInternetDatabaseBypassCounterexample constructs a Counterexample for an internet database reachability violation.
// Safe on nil dst or match.
func newInternetDatabaseBypassCounterexample(dst *Host, match *RuleMatch) *Counterexample {
	if dst == nil || match == nil {
		return nil
	}
	dstID := dst.SafeID()
	return newSGCounterexample(
		match.InternetSource(), dstID, match.Port, match.PathType, match,
		formatInternetDatabaseExplanation(dstID, match.RuleSource, match.Port, match.SecurityGroupID),
		formatInternetDatabaseRemediation(match.SecurityGroupID),
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
	return ce, ReasonCrossVPCDatabaseBypass
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

		return ce, ReasonInternetDatabaseBypass
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

	result := newBastionProofResult(PropertyTransitiveSSH, len(prod), len(bastions))

	for _, dst := range prod {
		if ce, reason := g.findHostTransitiveSSHBypass(dst, port); ce != nil {
			return result.sat(ce, reason, start)
		}
	}

	return result.unsat(InterpretationTransitiveSSHUNSAT, start)
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

const (
	// InterpretationTransitiveSSHUNSAT is the sound UNSAT interpretation returned when no non-bastion relay can bridge to production.
	InterpretationTransitiveSSHUNSAT = "No transitive SSH paths to production exist — no non-bastion relay can bridge to production."
	// ReasonTransitiveSSHInternetBypass is the explanation returned when an internet-facing host can relay SSH to production.
	ReasonTransitiveSSHInternetBypass = "Transitive SSH path exists — a non-bastion host reachable from the internet can relay SSH to production." //nolint:gosec // G101 false positive: explanation message, not a credential
	// ReasonTransitiveSSHInternalBypass is the explanation returned when an internal intermediate host can relay SSH to production.
	ReasonTransitiveSSHInternalBypass = "Transitive SSH path exists — a non-bastion host can relay SSH to production via an intermediate host." //nolint:gosec // G101 false positive: explanation message, not a credential
)

func (g *Graph) findRelayTransitiveSSHBypass(relay, dst *Host, port int, relayMatch *RuleMatch) (*Counterexample, string) {
	if g == nil || relay == nil || dst == nil || relayMatch == nil {
		return nil, ""
	}
	if ce := g.findTransitiveInternetBypass(relay, dst, port, relayMatch); ce != nil {
		return ce, ReasonTransitiveSSHInternetBypass
	}
	if ce := g.findTransitiveInternalHostBypass(relay, dst, port, relayMatch); ce != nil {
		return ce, ReasonTransitiveSSHInternalBypass
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
	return newTransitiveInternetBypassCounterexample(relay, dst, port, match, relayMatch)
}

// formatTransitiveInternetRemediation formats remediation advice for an internet-facing transitive SSH relay.
func formatTransitiveInternetRemediation(ruleSource, relayID, dstID string) string {
	return fmt.Sprintf("Remove SSH ingress from %s on %s or remove its access to production host %s.", ruleSource, relayID, dstID)
}

// formatTransitiveInternalRemediation formats remediation advice for an internal transitive SSH relay.
func formatTransitiveInternalRemediation(srcID, relayID, dstID string) string {
	return fmt.Sprintf("Remove SSH access from %s to %s or from %s to production host %s.", srcID, relayID, relayID, dstID)
}

// formatTransitiveInternetHopLead formats the lead-in clause of an internet-facing transitive explanation.
func formatTransitiveInternetHopLead(relayID string) string {
	return fmt.Sprintf("Host %s is SSH-accessible from the internet and", relayID)
}

// formatTransitiveInternalHopLead formats the lead-in clause of an internal transitive explanation.
func formatTransitiveInternalHopLead(srcID, relayID string) string {
	return fmt.Sprintf("Host %s can reach %s, which", srcID, relayID)
}

// newTransitiveInternetBypassCounterexample constructs a Counterexample for an internet-facing transitive SSH relay violation.
// Safe on nil relay, dst, match, or relayMatch.
func newTransitiveInternetBypassCounterexample(relay, dst *Host, port int, match, relayMatch *RuleMatch) *Counterexample {
	if relay == nil || dst == nil || match == nil || relayMatch == nil {
		return nil
	}
	relayID, dstID := relay.SafeID(), dst.SafeID()
	return newTransitiveCounterexample(
		match.RuleSource,
		"internet",
		formatTransitiveInternetHopLead(relayID),
		relay, dst, port, relayMatch,
		formatTransitiveInternetRemediation(match.RuleSource, relayID, dstID),
	)
}

func (g *Graph) findTransitiveInternalBypass(src, relay, dst *Host, port int, relayMatch *RuleMatch) *Counterexample {
	match := g.Reachability(src, relay, port)
	if match == nil || relayMatch == nil {
		return nil
	}
	return newTransitiveInternalBypassCounterexample(src, relay, dst, port, match, relayMatch)
}

// newTransitiveInternalBypassCounterexample constructs a Counterexample for an internal transitive SSH relay violation.
// Safe on nil src, relay, dst, match, or relayMatch.
func newTransitiveInternalBypassCounterexample(src, relay, dst *Host, port int, match, relayMatch *RuleMatch) *Counterexample {
	if src == nil || relay == nil || dst == nil || match == nil || relayMatch == nil {
		return nil
	}
	srcID, relayID, dstID := src.SafeID(), relay.SafeID(), dst.SafeID()
	return newTransitiveCounterexample(
		srcID,
		srcID,
		formatTransitiveInternalHopLead(srcID, relayID),
		relay, dst, port, relayMatch,
		formatTransitiveInternalRemediation(srcID, relayID, dstID),
	)
}

// RouteBypassesFirewall reports whether the route targets an internet gateway
// directly without traversing a firewall endpoint. Safe on nil receiver.
func (g *Graph) RouteBypassesFirewall(route Route) bool {
	if g == nil {
		return false
	}
	return route.IsInternetGateway() && !g.HasFirewall(route.TargetID)
}

const (
	// ReasonFirewallBypass is the explanation returned when a private subnet routes directly to an IGW.
	ReasonFirewallBypass = "Firewall bypass exists — private subnet routes internet traffic directly to an internet gateway." //nolint:gosec // G101 false positive: explanation message, not a credential
	// InterpretationFirewallMandatory is the interpretation returned when all private subnets route internet traffic through firewall endpoints.
	InterpretationFirewallMandatory = "All private subnets route internet traffic through a Network Firewall endpoint."
)

// ProveFirewallMandatory checks that all private subnets route internet
// traffic through a Network Firewall endpoint. Returns UNSAT if all
// egress routes through firewall, SAT if a bypass exists.
func (g *Graph) ProveFirewallMandatory() (*ProofResult, error) {
	start := time.Now()

	privateSubnets := g.PrivateSubnets()
	if len(privateSubnets) == 0 {
		return nil, vacuousErr("no subnets tagged stave:subnet-type=private")
	}
	if g.FirewallCount() == 0 {
		return nil, vacuousErr("no firewall endpoints found — cannot prove firewall routing")
	}

	result := newProofResult(PropertyFirewallMandatory, map[string]int{"private_subnets": len(privateSubnets), "firewall_endpoints": g.FirewallCount()})

	for _, sub := range privateSubnets {
		if !sub.HasRouteTable() {
			return nil, vacuousErr("subnet %s has no route table association — cannot prove firewall routing", sub.ID)
		}
		if ce := g.findSubnetFirewallBypass(sub); ce != nil {
			return result.sat(ce, ReasonFirewallBypass, start)
		}
	}

	return result.unsat(InterpretationFirewallMandatory, start)
}

func (g *Graph) findSubnetBypassingRoute(sub *Subnet) (Route, bool) {
	route, ok := g.DefaultRouteForSubnet(sub)
	if ok && g.RouteBypassesFirewall(route) {
		return route, true
	}
	return Route{}, false
}

// formatFirewallBypassExplanation formats the explanation of a direct IGW firewall bypass.
func formatFirewallBypassExplanation(subnetID, dest, igwID, rtID string) string {
	return fmt.Sprintf("Subnet %s has a %s route to IGW %s in route table %s without passing through a Network Firewall endpoint.", subnetID, dest, igwID, rtID)
}

// formatFirewallBypassRemediation formats the remediation advice for a direct IGW firewall bypass.
func formatFirewallBypassRemediation(dest, rtID, igwID string) string {
	return fmt.Sprintf("Change the %s route in %s to target a Network Firewall endpoint instead of %s.", dest, rtID, igwID)
}

// newFirewallBypassCounterexample constructs a Counterexample for a direct-to-IGW firewall bypass.
// Safe on nil sub.
func newFirewallBypassCounterexample(sub *Subnet, route Route) *Counterexample {
	if sub == nil {
		return nil
	}
	subID := sub.SafeID()
	rtID := sub.SafeRouteTableID()
	explanation := formatFirewallBypassExplanation(subID, route.Destination, route.TargetID, rtID)
	remediation := formatFirewallBypassRemediation(route.Destination, rtID, route.TargetID)
	return newRouteCounterexample(sub, route, PathTypeDirectIGW, explanation, remediation)
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

// newSinkRouteTarget constructs a RouteTarget representing a definite internet egress sink.
func newSinkRouteTarget(targetID string) RouteTarget {
	return RouteTarget{Class: routeSink, TargetID: targetID}
}

// newNonSinkRouteTarget constructs a RouteTarget representing non-egress (local) routing.
func newNonSinkRouteTarget(targetID string) RouteTarget {
	return RouteTarget{Class: routeNonSink, TargetID: targetID}
}

// newGatedRouteTarget constructs a RouteTarget representing an unresolvable or ambiguous route target.
func newGatedRouteTarget(reason, targetID string) RouteTarget {
	return RouteTarget{Class: routeGated, Reason: reason, TargetID: targetID}
}

// ClassifyTarget classifies a default-route target for the
// transitive-egress prover. The default arm is Gated — an unrecognized
// target_type can only ever widen the answer, never hide a path.
func (r Route) ClassifyTarget() RouteTarget {
	switch r.TargetType {
	case "nat", "igw", "eigw":
		return newSinkRouteTarget(r.TargetID)
	case "local":
		return newNonSinkRouteTarget(r.TargetID)
	case "tgw":
		return newGatedRouteTarget("TGW route table not resolved", r.TargetID)
	case "vgw":
		return newGatedRouteTarget("on-premises egress not observable", r.TargetID)
	case "vpce":
		return newGatedRouteTarget("firewall policy not evaluated", r.TargetID)
	case "instance", "eni":
		return newGatedRouteTarget("NAT instance or appliance forwarding not observable", r.TargetID)
	default:
		return newGatedRouteTarget("unrecognized route target", r.TargetID)
	}
}

const (
	// ReasonTransitiveEgressBypass is the explanation returned when an isolated workload can reach a host with internet egress.
	ReasonTransitiveEgressBypass = "Transitive internet egress path exists — an isolated workload can reach a host with internet egress." //nolint:gosec // G101 false positive: explanation message, not a credential
	// ReasonTransitiveEgressGated is the explanation returned when a transitive egress path depends on an unobservable route target.
	ReasonTransitiveEgressGated = "A path reaches a route target the snapshot cannot resolve. The verdict depends on an observation not yet available."
	// InterpretationTransitiveEgressUNSAT is the sound UNSAT interpretation returned when no isolated workload reaches the internet through an intermediate host.
	InterpretationTransitiveEgressUNSAT = "No isolated workload reaches the internet through an intermediate host, over security-group ingress reachability. Sound under that model: NACL denies and security-group egress rules are not evaluated, so a SAT counterexample may be blocked in practice, but UNSAT does not depend on them. Network-layer only — IAM-layer service paths (Lambda invoke, SSM, S3 replication, VPC endpoints to request-making services) are not evaluated. Single-region snapshot; run per region."
)

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

	result := newProofResult(PropertyTransitiveEgress, map[string]int{
		"isolated_hosts": len(isolated),
		"sink_hosts":     candidates.SinkCount(),
		"gated_hosts":    candidates.GatedCount(),
	})

	if ce := g.findTransitiveEgressBypass(isolated, candidates.sinks); ce != nil {
		return result.sat(ce, ReasonTransitiveEgressBypass, start)
	}

	if ce := g.findTransitiveEgressGated(isolated, candidates.gated); ce != nil {
		return result.gated(ce, ReasonTransitiveEgressGated, start)
	}

	return result.unsat(InterpretationTransitiveEgressUNSAT, start)
}

// formatEgressReachabilityPrefix formats the reachability statement of a transitive egress explanation.
func formatEgressReachabilityPrefix(isoID, targetID string, port int) string {
	return fmt.Sprintf("Isolated host %s can reach %s on port %s.", isoID, targetID, FormatPort(port))
}

// formatRemoveAccessRemediation formats the remediation advice to remove network access between two hosts.
func formatRemoveAccessRemediation(isoID, targetID string) string {
	return fmt.Sprintf("Remove network access from %s to %s", isoID, targetID)
}

// formatEgressBypassRemediation formats the remediation advice for a transitive egress bypass.
func formatEgressBypassRemediation(isoID, hostID string) string {
	return fmt.Sprintf("%s, or remove %s's internet egress route.",
		formatRemoveAccessRemediation(isoID, hostID), hostID)
}

// formatEgressGatedRemediation formats the remediation advice for a gated transitive egress path.
func formatEgressGatedRemediation(targetType, targetID, isoID, hostID string) string {
	return fmt.Sprintf("Provide observation for %s %s to settle the verdict, or remove network access from %s to %s.",
		targetType, targetID, isoID, hostID)
}

// formatEgressBypassExplanation formats the explanation of a transitive egress bypass through an intermediate host.
func formatEgressBypassExplanation(isoID, hostID, dest, target string, port int) string {
	return fmt.Sprintf("%s %s's subnet routes %s to %s. Two-hop path: %s → %s → internet.",
		formatEgressReachabilityPrefix(isoID, hostID, port),
		hostID, dest, target, isoID, hostID)
}

func newEgressBypassCounterexample(iso *Host, s egressCandidate, match *RuleMatch) *Counterexample {
	if iso == nil || s.host == nil || match == nil {
		return nil
	}
	isoID, hostID := iso.SafeID(), s.HostID()
	explanation := formatEgressBypassExplanation(isoID, hostID, s.RouteDestination(), s.RouteTarget(), match.Port)
	remediation := formatEgressBypassRemediation(isoID, hostID)
	return newSGCounterexample(isoID, hostID, match.Port, PathTypeTransitiveEgress, match, explanation, remediation)
}

// formatEgressGatedExplanation formats the explanation of a gated transitive egress path.
func formatEgressGatedExplanation(isoID, hostID, dest, target, reason string, port int) string {
	return fmt.Sprintf("%s %s's subnet routes %s to %s (%s).",
		formatEgressReachabilityPrefix(isoID, hostID, port),
		hostID, dest, target, reason)
}

func newEgressGatedCounterexample(iso *Host, gc egressCandidate, match *RuleMatch) *Counterexample {
	if iso == nil || gc.host == nil || match == nil {
		return nil
	}
	isoID, hostID := iso.SafeID(), gc.HostID()
	explanation := formatEgressGatedExplanation(isoID, hostID, gc.RouteDestination(), gc.RouteTarget(), gc.TargetReason(), match.Port)
	remediation := formatEgressGatedRemediation(gc.RouteTargetType(), gc.TargetID(), isoID, hostID)
	return newSGCounterexample(isoID, hostID, match.Port, PathTypeGatedEgress, match, explanation, remediation)
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

// HostID returns the candidate host's ID, or "" if host is nil.
func (c egressCandidate) HostID() string {
	return c.host.SafeID()
}

// RouteDestination returns the destination CIDR of the candidate's route.
func (c egressCandidate) RouteDestination() string {
	return c.route.Destination
}

// RouteTarget returns the formatted target of the candidate's route.
func (c egressCandidate) RouteTarget() string {
	return c.route.Target()
}

// RouteTargetType returns the target type of the candidate's route.
func (c egressCandidate) RouteTargetType() string {
	return c.route.TargetType
}

// TargetReason returns the resolution reason of the candidate's route target.
func (c egressCandidate) TargetReason() string {
	return c.target.Reason
}

// TargetID returns the target identifier of the candidate's route target.
func (c egressCandidate) TargetID() string {
	return c.target.TargetID
}

// IsSink reports whether the candidate route target is a definite internet sink.
func (c egressCandidate) IsSink() bool {
	return c.target.IsSink()
}

// IsGated reports whether the candidate route target depends on unobservable evidence.
func (c egressCandidate) IsGated() bool {
	return c.target.IsGated()
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
func (p *egressCandidatePartition) IsEmpty() bool {
	if p == nil {
		return true
	}
	return len(p.sinks) == 0 && len(p.gated) == 0
}

// SinkCount returns the number of sink candidates.
func (p *egressCandidatePartition) SinkCount() int {
	if p == nil {
		return 0
	}
	return len(p.sinks)
}

// GatedCount returns the number of gated candidates.
func (p *egressCandidatePartition) GatedCount() int {
	if p == nil {
		return 0
	}
	return len(p.gated)
}

func (p *egressCandidatePartition) add(c egressCandidate) {
	if p == nil {
		return
	}
	if c.IsSink() {
		p.sinks = append(p.sinks, c)
	} else if c.IsGated() {
		p.gated = append(p.gated, c)
	}
}

// findEgressCandidates identifies all non-isolated hosts with default routes,
// partitioned into sink candidates (definite egress) and gated candidates (observable-dependent).
func (g *Graph) findEgressCandidates() egressCandidatePartition {
	if g == nil {
		return egressCandidatePartition{}
	}
	var p egressCandidatePartition
	for _, h := range g.allHosts() {
		if c, ok := g.hostEgressCandidate(h); ok {
			p.add(c)
		}
	}
	return p
}
