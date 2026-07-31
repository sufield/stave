package iam

import (
	"slices"
	"strings"
)

// ActionRiskCategory classifies IAM actions by security risk.
type ActionRiskCategory int

const (
	ActionCredentialExposure ActionRiskCategory = iota + 1
	ActionDataAccess
	ActionPrivEsc
	ActionResourceExposure
	ActionDiscovery
)

func (c ActionRiskCategory) String() string {
	switch c {
	case ActionCredentialExposure:
		return "CredentialExposure"
	case ActionDataAccess:
		return "DataAccess"
	case ActionPrivEsc:
		return "PrivEsc"
	case ActionResourceExposure:
		return "ResourceExposure"
	case ActionDiscovery:
		return "Discovery"
	}
	return "Unknown"
}

// ActionClassification holds the risk categories for a single IAM action.
type ActionClassification struct {
	Action     string
	Categories []ActionRiskCategory
	Source     string // "farris" or "stave"
}

// SensitiveActionRegistry provides lookups for IAM action risk classification.
type SensitiveActionRegistry struct {
	actions  map[string][]ActionRiskCategory
	byPrefix map[string][]string // service prefix → actions
}

// NewRegistry builds a registry from the given classifications.
func NewRegistry(entries []ActionClassification) *SensitiveActionRegistry {
	r := &SensitiveActionRegistry{
		actions:  make(map[string][]ActionRiskCategory, len(entries)),
		byPrefix: make(map[string][]string),
	}
	for _, e := range entries {
		key := strings.ToLower(e.Action)
		if existing, ok := r.actions[key]; ok {
			for _, cat := range e.Categories {
				if !slices.Contains(existing, cat) {
					existing = append(existing, cat)
				}
			}
			r.actions[key] = existing
		} else {
			r.actions[key] = e.Categories
			if idx := strings.IndexByte(key, ':'); idx > 0 {
				prefix := key[:idx]
				r.byPrefix[prefix] = append(r.byPrefix[prefix], key)
			}
		}
	}
	return r
}

// DefaultRegistry returns the singleton registry seeded from
// Farris's sensitive_iam_actions plus Stave gap additions.
func DefaultRegistry() *SensitiveActionRegistry {
	return NewRegistry(defaultActions)
}

// Classify returns the risk categories for an IAM action.
// Returns nil for unclassified actions.
func (r *SensitiveActionRegistry) Classify(action string) []ActionRiskCategory {
	return r.actions[strings.ToLower(action)]
}

// ClassifyWildcard handles wildcard patterns like "s3:Get*" or "s3:*".
// Returns the union of categories for all matching actions.
func (r *SensitiveActionRegistry) ClassifyWildcard(pattern string) []ActionRiskCategory {
	p := strings.ToLower(pattern)

	// Exact match first.
	if cats := r.actions[p]; cats != nil {
		return cats
	}

	// Full wildcard.
	if p == "*" {
		return r.allCategories()
	}

	// "service:*" — all actions for that service.
	if idx := strings.IndexByte(p, ':'); idx > 0 {
		suffix := p[idx+1:]
		prefix := p[:idx]
		if suffix == "*" {
			return r.categoriesForPrefix(prefix)
		}
		// "service:Verb*" — match prefix.
		if strings.HasSuffix(suffix, "*") {
			actionPrefix := p[:len(p)-1]
			return r.categoriesMatching(prefix, actionPrefix)
		}
	}

	return nil
}

// HasDataAccess returns true if the action or pattern includes any
// DataAccess-classified action.
func (r *SensitiveActionRegistry) HasDataAccess(actionOrPattern string) bool {
	return r.hasCategory(actionOrPattern, ActionDataAccess)
}

// HasCredentialExposure returns true if the action or pattern includes
// any CredentialExposure-classified action.
func (r *SensitiveActionRegistry) HasCredentialExposure(actionOrPattern string) bool {
	return r.hasCategory(actionOrPattern, ActionCredentialExposure)
}

// HasPrivEsc returns true if the action or pattern includes any
// PrivEsc-classified action.
func (r *SensitiveActionRegistry) HasPrivEsc(actionOrPattern string) bool {
	return r.hasCategory(actionOrPattern, ActionPrivEsc)
}

// CountByCategory counts actions in the given category from a list.
func (r *SensitiveActionRegistry) CountByCategory(
	actions []string, category ActionRiskCategory,
) int {
	n := 0
	for _, a := range actions {
		if slices.Contains(r.Classify(a), category) {
			n++
		}
	}
	return n
}

// Len returns the number of classified actions.
func (r *SensitiveActionRegistry) Len() int { return len(r.actions) }

func (r *SensitiveActionRegistry) hasCategory(actionOrPattern string, cat ActionRiskCategory) bool {
	var cats []ActionRiskCategory
	if strings.ContainsRune(actionOrPattern, '*') {
		cats = r.ClassifyWildcard(actionOrPattern)
	} else {
		cats = r.Classify(actionOrPattern)
	}
	return slices.Contains(cats, cat)
}

func (r *SensitiveActionRegistry) allCategories() []ActionRiskCategory {
	return []ActionRiskCategory{
		ActionCredentialExposure, ActionDataAccess,
		ActionPrivEsc, ActionResourceExposure, ActionDiscovery,
	}
}

func (r *SensitiveActionRegistry) categoriesForPrefix(prefix string) []ActionRiskCategory {
	seen := make(map[ActionRiskCategory]bool)
	for _, a := range r.byPrefix[prefix] {
		for _, c := range r.actions[a] {
			seen[c] = true
		}
	}
	return setToSlice(seen)
}

func (r *SensitiveActionRegistry) categoriesMatching(prefix, actionPrefix string) []ActionRiskCategory {
	seen := make(map[ActionRiskCategory]bool)
	for _, a := range r.byPrefix[prefix] {
		if strings.HasPrefix(a, actionPrefix) {
			for _, c := range r.actions[a] {
				seen[c] = true
			}
		}
	}
	return setToSlice(seen)
}

func setToSlice(m map[ActionRiskCategory]bool) []ActionRiskCategory {
	if len(m) == 0 {
		return nil
	}
	out := make([]ActionRiskCategory, 0, len(m))
	for _, c := range []ActionRiskCategory{
		ActionCredentialExposure, ActionDataAccess,
		ActionPrivEsc, ActionResourceExposure, ActionDiscovery,
	} {
		if m[c] {
			out = append(out, c)
		}
	}
	return out
}

// EdgeType classifies a reachability edge by the risk category
// of the action that enables it. Defined here for future Datalog
// integration; consumed by reasoning/souffle/iam rules.
type EdgeType int

const (
	EdgeMetadata    EdgeType = iota // Get*/List*/Describe*
	EdgeDataAccess                  // s3:GetObject, etc.
	EdgeCredential                  // sts:AssumeRole, etc.
	EdgePrivEsc                     // iam:PassRole, etc.
	EdgeResExposure                 // s3:PutBucketPolicy, etc.
	EdgeDiscovery                   // iam:ListUsers, iam:GetUserPolicy, etc.
)
