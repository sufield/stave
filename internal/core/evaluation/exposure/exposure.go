package exposure

import (
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
)

// Source identifies what mechanism exposed a prefix as publicly readable.
type Source struct {
	Kind Kind
	ID   kernel.StatementID
}

// Kind identifies the evidence mechanism (for example, identity or resource).
type Kind string

// Exposure evidence source kind constants.
const (
	SourceIdentity        Kind = "identity"
	SourceResource        Kind = "resource"
	SourceMissingEvidence Kind = "missing_evidence"
)

// NewSource constructs a normalized evidence source.
func NewSource(kind Kind, sourceID kernel.StatementID) Source {
	return Source{
		Kind: kind,
		ID:   kernel.StatementID(strings.TrimSpace(string(sourceID))),
	}
}

func (s Source) String() string {
	if s.ID == "" {
		return string(s.Kind)
	}
	return string(s.Kind) + ":" + string(s.ID)
}

// ComplianceReport captures whether a prefix is publicly exposed and, if so,
// the evidence source that proved it.
type ComplianceReport struct {
	Exposed      bool
	Inconclusive bool
	Source       Source
}

func (r ComplianceReport) String() string { return r.Source.String() }

// safeResult is the pre-built audit result indicating no exposure.
// Callers reach it via NewSafeResult so the value cannot be mutated
// by a misbehaving consumer.
var safeResult = ComplianceReport{Exposed: false}

// NewSafeResult returns a copy of the canonical "no exposure"
// compliance report. Each call yields an independent value safe
// for the caller to mutate.
func NewSafeResult() ComplianceReport {
	return safeResult
}

// Grant pairs a scope (e.g. "*", "invoices/") with the statement ID that granted it.
type Grant struct {
	Scope    kernel.ObjectPrefix
	SourceID kernel.StatementID
}

// Covers reports whether this grant's scope matches the given prefix.
func (g Grant) Covers(prefix kernel.ObjectPrefix) bool {
	return g.Scope.Matches(prefix)
}

// Evidence returns the evidence source for this grant, qualified by SourceID.
func (g Grant) Evidence() Source {
	return NewSource(SourceIdentity, g.SourceID)
}

// Grants is an ordered list of policy grants.
type Grants []Grant

// FindMatch returns the first grant whose scope covers prefix, or nil.
func (gs Grants) FindMatch(prefix kernel.ObjectPrefix) *Grant {
	for i := range gs {
		if gs[i].Covers(prefix) {
			return &gs[i]
		}
	}
	return nil
}

// AccessSummary contains normalized evidence used for prefix exposure checks.
type AccessSummary struct {
	HasIdentityEvidence bool
	HasResourceEvidence bool

	// Identity-bound access (e.g., IAM, Service Policies)
	IdentityGrants      Grants
	IdentityReadBlocked bool

	// Resource-bound access (e.g., Bucket Policies, ACLs)
	ResourceReadAll     bool
	ResourceReadBlocked bool
}

// IdentityAllowsPublicRead reports whether identity-bound evidence permits public read.
func (f AccessSummary) IdentityAllowsPublicRead() bool {
	return f.HasIdentityEvidence && !f.IdentityReadBlocked
}

// ResourceAllowsPublicRead reports whether resource-bound evidence permits public read.
func (f AccessSummary) ResourceAllowsPublicRead() bool {
	return f.HasResourceEvidence && f.ResourceReadAll && !f.ResourceReadBlocked
}

// LacksEvidence reports whether neither identity nor resource evidence is available.
func (f AccessSummary) LacksEvidence() bool {
	return !f.HasIdentityEvidence && !f.HasResourceEvidence
}

// CheckExposure determines whether a protected prefix is effectively publicly readable.
func (f AccessSummary) CheckExposure(prefix kernel.ObjectPrefix) ComplianceReport {
	// Rule 1: Explicit identity grants take precedence.
	if f.IdentityAllowsPublicRead() {
		if grant := f.IdentityGrants.FindMatch(prefix); grant != nil {
			return ComplianceReport{Exposed: true, Source: grant.Evidence()}
		}
	}

	// Rule 2: Resource-bound access can expose the entire asset.
	if f.ResourceAllowsPublicRead() {
		return ComplianceReport{Exposed: true, Source: NewSource(SourceResource, "")}
	}

	// Rule 3: Missing evidence → inconclusive, not exposed.
	if f.LacksEvidence() {
		return ComplianceReport{Inconclusive: true, Source: NewSource(SourceMissingEvidence, "")}
	}

	return NewSafeResult()
}
