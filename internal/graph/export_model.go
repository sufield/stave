package graph

import (
	"strings"
)

// ontologyBaseIRI is the namespace IRI all Stave-coined classes and
// properties live under. The trailing '#' makes it a hash-IRI namespace
// so terms compose as <urn:stave:ontology#Finding>, <urn:stave:ontology#violates>.
const ontologyBaseIRI = "urn:stave:ontology#"

// resourceBaseIRI is the namespace for instance IRIs (one node per
// resource, finding, etc.). Distinct from ontologyBaseIRI so the data
// graph and the schema graph never collide on a term.
const resourceBaseIRI = "urn:stave:"

// Severity → numeric weight. Used by GDS algorithms (centrality,
// shortest path, influence propagation) that need a scalar edge
// weight rather than a categorical label. Higher = more dangerous.
var severityWeights = map[string]float64{
	"critical": 10.0,
	"high":     7.0,
	"medium":   4.0,
	"low":      1.0,
	"none":     0.0,
}

// SeverityWeight returns the GDS-friendly numeric weight for a
// categorical severity string. Unknown severities return 0 so an
// algorithm running over the graph treats them as non-edges of the
// weighted view rather than throwing.
func SeverityWeight(severity string) float64 {
	if w, ok := severityWeights[strings.ToLower(severity)]; ok {
		return w
	}
	return 0.0
}

// RDFNode is the export-shaped representation of a graph node. The
// JSON tags drive JSON-LD; the same struct is consumed by the GraphML
// serializer. Fields are intentionally a small flat shape — JSON-LD
// nesting is handled by the @context, not by struct nesting.
type RDFNode struct {
	ID         string         `json:"@id"`
	Type       string         `json:"@type"`
	Properties map[string]any `json:"-"`
}

// RDFEdge is the export-shaped representation of a graph edge.
// JSON-LD does not have first-class edges; the JSON-LD serializer
// emits each edge as a triple (subject IRI, predicate IRI, object
// IRI) inside the @graph array, optionally annotated with a
// reification node when edge attributes are present. GraphML keeps
// edges first-class.
type RDFEdge struct {
	From       string         // subject IRI
	To         string         // object IRI
	Predicate  string         // predicate IRI (full, not prefixed)
	Properties map[string]any // optional, e.g. weight + chain_severity
	Shortcut   bool           // true for materialized algorithm shortcuts
}

// RDFGraph is the export-shaped graph model. Built from an internal
// graph.GraphData by mapToRDFGraph; consumed by MarshalJSONLD and
// MarshalGraphML.
type RDFGraph struct {
	OntologyIRI   string         // urn:stave:ontology
	GeneratedAt   string         // RFC3339
	Nodes         []RDFNode      // sorted by ID for determinism
	Edges         []RDFEdge      // sorted by (From, Predicate, To)
	UnmappedEdges []UnmappedEdge // edges dropped because Type was outside the wireToPredicate vocabulary
}

// --- URI builders ----------------------------------------------------

// stavePrefix is the URI prefix all Stave instance IRIs share.
// Concatenated with the per-class shape from the user's spec:
//
//	stave:bucket/{account}/{bucket-name}
//	stave:finding/{hash}
//	stave:invariant/{category}.{number}
//
// Implemented with explicit constants so a typo in the prefix
// surfaces at compile time, not at silent IRI drift.
const (
	bucketPrefix      = resourceBaseIRI + "bucket/"
	resourcePrefix    = resourceBaseIRI + "resource/"
	findingPrefix     = resourceBaseIRI + "finding/"
	invariantPrefix   = resourceBaseIRI + "invariant/"
	scopePrefix       = resourceBaseIRI + "account/"
	chainPrefix       = resourceBaseIRI + "chain/"
	capabilityPrefix  = resourceBaseIRI + "capability/"
	requirementPrefix = resourceBaseIRI + "requirement/"
	remediationPrefix = resourceBaseIRI + "remediation/"
	identityPrefix    = resourceBaseIRI + "identity/"
)

// BucketIRI builds the IRI for an S3 bucket node.
func BucketIRI(account, bucket string) string {
	return bucketPrefix + iriSegment(account) + "/" + iriSegment(bucket)
}

// ResourceIRI builds an IRI for a generic non-bucket resource. The
// identifier is typically the asset's full ARN; iriSegment escapes
// reserved characters so the IRI stays well-formed.
func ResourceIRI(arn string) string {
	return resourcePrefix + iriSegment(arn)
}

// FindingIRI builds the IRI for a finding from its hash/ID.
func FindingIRI(findingID string) string {
	return findingPrefix + iriSegment(findingID)
}

// InvariantIRI builds the IRI for an invariant/control. category and
// number can be derived by splitting a full control ID on the last
// '.', or both passed in by the caller. The exporter splits the
// internal "CTL.S3.PUBLIC.001" into ("CTL.S3.PUBLIC", "001"). When
// either component is empty (e.g. a non-standard control ID with no
// dot separator), drop the dot so the IRI does not gain a leading
// or trailing "." that downstream RDF parsers reject.
func InvariantIRI(category, number string) string {
	switch {
	case category == "" && number == "":
		return invariantPrefix
	case category == "":
		return invariantPrefix + iriSegment(number)
	case number == "":
		return invariantPrefix + iriSegment(category)
	default:
		return invariantPrefix + iriSegment(category) + "." + iriSegment(number)
	}
}

// ScopeIRI builds the IRI for a tenant scope (account).
func ScopeIRI(accountID string) string { return scopePrefix + iriSegment(accountID) }

// ChainIRI builds the IRI for a threat chain.
func ChainIRI(chainID string) string { return chainPrefix + iriSegment(chainID) }

// CapabilityIRI builds the IRI for an attacker capability.
func CapabilityIRI(chainID string) string { return capabilityPrefix + iriSegment(chainID) }

// RequirementIRI builds the IRI for a compliance requirement.
func RequirementIRI(framework, reqID string) string {
	return requirementPrefix + iriSegment(framework) + "/" + iriSegment(reqID)
}

// RemediationIRI builds the IRI for a remediation action.
func RemediationIRI(findingID string) string { return remediationPrefix + iriSegment(findingID) }

// IdentityIRI builds the IRI for an identity.
func IdentityIRI(identityID string) string { return identityPrefix + iriSegment(identityID) }

// iriSegment percent-encodes the IRI-reserved characters that the
// internal IDs (ARNs especially) carry — '/', ':', '?', '#', '%'.
// Letters, digits, '.', '-', '_' pass through unchanged so URIs stay
// human-readable. Hand-rolled rather than using net/url because
// net/url is path-aware and would treat ARNs as full URLs.
func iriSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '.', c == '-', c == '_', c == '~':
			b.WriteByte(c)
		default:
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// --- Predicate IRIs --------------------------------------------------
//
// Centralized so the JSON-LD context, the GraphML edge labels, and
// the mapping layer all reference the same constants.

const (
	predTargets             = ontologyBaseIRI + "targets"
	predHasFinding          = ontologyBaseIRI + "hasFinding"
	predViolatesInvariant   = ontologyBaseIRI + "violatesInvariant"
	predViolates            = ontologyBaseIRI + "violates"
	predViolatesRequirement = ontologyBaseIRI + "violatesRequirement"
	predMapsTo              = ontologyBaseIRI + "mapsTo"
	predHasRemediation      = ontologyBaseIRI + "hasRemediation"
	predMemberOf            = ontologyBaseIRI + "memberOf"
	predProduces            = ontologyBaseIRI + "produces"
	predBelongsToScope      = ontologyBaseIRI + "belongsToScope"
	predHasEffectiveAccess  = ontologyBaseIRI + "hasEffectiveAccess"
	predCanImpersonate      = ontologyBaseIRI + "canImpersonate"
	predGovernedBy          = ontologyBaseIRI + "governedBy"
)

// wireToPredicate maps the existing GraphData edge type strings (the
// "wire names" — TARGETS, MEMBER_OF, etc.) to ontology predicate IRIs.
// Single source of truth: changing the wire name on the internal
// graph requires a one-line change here. Edges whose wire name is
// not in this table are dropped from the RDF export and logged.
var wireToPredicate = map[string]string{
	"TARGETS":              predTargets,
	"VIOLATES":             predViolatesRequirement,
	"MAPS_TO":              predMapsTo,
	"BELONGS_TO_SCOPE":     predBelongsToScope,
	"MEMBER_OF":            predMemberOf,
	"PRODUCES":             predProduces,
	"HAS_REMEDIATION":      predHasRemediation,
	"HAS_EFFECTIVE_ACCESS": predHasEffectiveAccess,
	"CAN_IMPERSONATE":      predCanImpersonate,
	"GOVERNED_BY":          predGovernedBy,
}

// shortcutPredicates are predicates Stave annotates with
// stave:isAlgorithmShortcut "true" in the JSON-LD output. The flag
// means "this edge was synthesized by the export layer to skip past
// intermediate nodes that the underlying graph contains" — only
// materialized resource→control edges qualify. The previous shape
// also marked predViolatesRequirement (the finding→requirement edge)
// as a shortcut, but that edge is a real first-class relationship in
// the source graph, not a synthesized skip-link, so consumers that
// filter on isAlgorithmShortcut were incorrectly seeing it as a
// shortcut. Keep this set tight: only include predicates that are
// produced by the shortcut-materialization pass.
var shortcutPredicates = map[string]bool{
	predViolates:           true,
	predHasEffectiveAccess: true,
}
