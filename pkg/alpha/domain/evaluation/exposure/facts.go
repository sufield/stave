package exposure

import (
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// Source identifies what mechanism exposed a prefix as publicly readable.
type Source struct {
	Kind Kind
	ID   kernel.StatementID
}

// Kind identifies the evidence mechanism (for example, identity or resource).
type Kind string

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

// Result captures whether a prefix is publicly exposed and, if so,
// the evidence source that proved it.
type Result struct {
	Exposed bool
	Source  Source
}

func (r Result) String() string { return r.Source.String() }

var SafeResult = Result{Exposed: false}

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

// Facts contains normalized evidence used for prefix exposure checks.
type Facts struct {
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
func (facts Facts) IdentityAllowsPublicRead() bool {
	return facts.HasIdentityEvidence && !facts.IdentityReadBlocked
}

// ResourceAllowsPublicRead reports whether resource-bound evidence permits public read.
func (facts Facts) ResourceAllowsPublicRead() bool {
	return facts.HasResourceEvidence && facts.ResourceReadAll && !facts.ResourceReadBlocked
}

// LacksEvidence reports whether neither identity nor resource evidence is available.
func (facts Facts) LacksEvidence() bool {
	return !facts.HasIdentityEvidence && !facts.HasResourceEvidence
}

// CheckExposure determines whether a protected prefix is effectively publicly readable.
func (facts Facts) CheckExposure(prefix kernel.ObjectPrefix) Result {
	// Rule 1: Explicit identity grants take precedence.
	if facts.IdentityAllowsPublicRead() {
		if grant := facts.IdentityGrants.FindMatch(prefix); grant != nil {
			return Result{Exposed: true, Source: grant.Evidence()}
		}
	}

	// Rule 2: Resource-bound access can expose the entire asset.
	if facts.ResourceAllowsPublicRead() {
		return Result{Exposed: true, Source: NewSource(SourceResource, "")}
	}

	// Rule 3: Fail closed on missing evidence.
	if facts.LacksEvidence() {
		return Result{Exposed: true, Source: NewSource(SourceMissingEvidence, "")}
	}

	return SafeResult
}

// ScopeMatchesPrefix reports whether scope covers prefix.
func ScopeMatchesPrefix(scope, prefix kernel.ObjectPrefix) bool {
	return scope.Matches(prefix)
}
