// Package builtin provides embedded control definitions compiled into the binary.
package builtin

import (
	"fmt"
	"slices"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Selector filters controls by scope tags and minimum severity.
type Selector struct {
	Tags        []string        // e.g. ["aws", "s3"]
	MinSeverity policy.Severity // SeverityNone means no severity filter
}

// ParseSelector parses a selector string like "aws/s3/severity:high+".
// Path segments match scope_tags. A trailing "severity:X+" sets minimum severity.
func ParseSelector(s string) (Selector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Selector{}, fmt.Errorf("empty selector")
	}

	parts := strings.Split(s, "/")
	sel := Selector{}

	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if after, ok := strings.CutPrefix(p, "severity:"); ok {
			sevStr := strings.TrimSuffix(after, "+")
			sev, err := policy.ParseSeverity(sevStr)
			if err != nil || sev == policy.SeverityNone {
				return Selector{}, fmt.Errorf("invalid severity %q (use: critical, high, medium, low, info)", sevStr)
			}
			sel.MinSeverity = sev
		} else {
			sel.Tags = append(sel.Tags, p)
		}
	}

	return sel, nil
}

// Matches returns true if the control satisfies all selector criteria.
// All tags must be present in the control's ScopeTags (case-insensitive).
// If MinSeverity is set, the control's severity must meet or exceed it.
func (sel Selector) Matches(ctl policy.ControlDefinition) bool {
	// Check severity first for a fast fail path.
	if sel.MinSeverity > policy.SeverityNone && !ctl.Severity.Gte(sel.MinSeverity) {
		return false
	}

	// Check scope tags: all selector tags must be present.
	for _, required := range sel.Tags {
		matched := slices.ContainsFunc(ctl.ScopeTags, func(tag kernel.ScopeTag) bool {
			return strings.EqualFold(string(tag), required)
		})
		if !matched {
			return false
		}
	}

	return true
}

// MatchesAny returns true if the control matches any of the given selectors.
func MatchesAny(ctl policy.ControlDefinition, selectors []Selector) bool {
	if len(selectors) == 0 {
		return true // no selectors = include all
	}
	return slices.ContainsFunc(selectors, func(sel Selector) bool {
		return sel.Matches(ctl)
	})
}
