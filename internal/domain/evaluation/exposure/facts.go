package exposure

import "strings"

// Source identifies what mechanism exposed a prefix as publicly readable.
type Source struct {
	Kind Kind
	ID   string
}

// Kind identifies the evidence mechanism (for example, policy or ACL).
type Kind string

const (
	SourcePolicy          Kind = "policy"
	SourceACL             Kind = "acl"
	SourceMissingEvidence Kind = "missing_evidence"
)

// NewSource constructs a normalized evidence source.
func NewSource(kind Kind, sourceID string) Source {
	return Source{
		Kind: kind,
		ID:   strings.TrimSpace(sourceID),
	}
}

func (s Source) String() string {
	if s.ID == "" {
		return string(s.Kind)
	}
	return string(s.Kind) + ":" + s.ID
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
	Scope    string
	SourceID string
}

// Covers reports whether this grant's scope matches the given prefix.
func (g Grant) Covers(prefix string) bool {
	return prefixScope(g.Scope).Matches(prefix)
}

// Evidence returns the evidence source for this grant, qualified by SourceID.
func (g Grant) Evidence() Source {
	return NewSource(SourcePolicy, g.SourceID)
}

// Grants is an ordered list of policy grants.
type Grants []Grant

// FindMatch returns the first grant whose scope covers prefix, or nil.
func (gs Grants) FindMatch(prefix string) *Grant {
	for i := range gs {
		if gs[i].Covers(prefix) {
			return &gs[i]
		}
	}
	return nil
}

// Facts contains normalized evidence used for prefix exposure checks.
type Facts struct {
	HasPolicyEvidence       bool
	HasACLEvidence          bool
	PolicyGrants            Grants
	PolicyPublicReadBlocked bool
	ACLPublicReadAll        bool
	ACLPublicReadBlocked    bool
}

// PolicyAllowsPublicRead reports whether policy evidence permits public read.
func (facts Facts) PolicyAllowsPublicRead() bool {
	return facts.HasPolicyEvidence && !facts.PolicyPublicReadBlocked
}

// ACLAllowsPublicRead reports whether ACL evidence permits public read.
func (facts Facts) ACLAllowsPublicRead() bool {
	return facts.HasACLEvidence && facts.ACLPublicReadAll && !facts.ACLPublicReadBlocked
}

// LacksEvidence reports whether neither policy nor ACL evidence is available.
func (facts Facts) LacksEvidence() bool {
	return !facts.HasPolicyEvidence && !facts.HasACLEvidence
}

// CheckExposure determines whether a protected prefix is effectively publicly readable.
func (facts Facts) CheckExposure(prefix string) Result {
	// Rule 1: Explicit policy grants take precedence.
	if facts.PolicyAllowsPublicRead() {
		if grant := facts.PolicyGrants.FindMatch(prefix); grant != nil {
			return Result{Exposed: true, Source: grant.Evidence()}
		}
	}

	// Rule 2: ACLs can expose the entire asset.
	if facts.ACLAllowsPublicRead() {
		return Result{Exposed: true, Source: NewSource(SourceACL, "")}
	}

	// Rule 3: Fail closed on missing evidence.
	if facts.LacksEvidence() {
		return Result{Exposed: true, Source: NewSource(SourceMissingEvidence, "")}
	}

	return SafeResult
}

// ScopeMatchesPrefix reports whether scope covers prefix.
func ScopeMatchesPrefix(scope, prefix string) bool {
	return prefixScope(scope).Matches(prefix)
}

type prefixScope string

func (s prefixScope) Matches(prefix string) bool {
	scopeValue := strings.TrimSpace(string(s))
	if scopeValue == "" {
		return false
	}
	if scopeValue == "*" {
		return true
	}
	if !strings.HasSuffix(scopeValue, "/") {
		scopeValue += "/"
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return strings.HasPrefix(prefix, scopeValue)
}
