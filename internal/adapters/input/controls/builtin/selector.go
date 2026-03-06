// Package builtin provides embedded control definitions compiled into the binary.
package builtin

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/domain/policy"
)

// BuiltinSelector filters controls by scope tags and minimum severity.
type BuiltinSelector struct {
	ScopeTags   []string        // e.g. ["aws", "s3"]
	MinSeverity policy.Severity // SeverityNone means no severity filter
}

// ParseSelector parses a selector string like "aws/s3/severity:high+".
// Path segments match scope_tags. A trailing "severity:X+" sets minimum severity.
func ParseSelector(s string) (BuiltinSelector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return BuiltinSelector{}, fmt.Errorf("empty selector")
	}

	parts := strings.Split(s, "/")
	sel := BuiltinSelector{}

	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if after, ok := strings.CutPrefix(p, "severity:"); ok {
			sevStr := strings.TrimSuffix(after, "+")
			sev := policy.ParseSeverity(sevStr)
			if sev == policy.SeverityNone {
				return BuiltinSelector{}, fmt.Errorf("invalid severity %q (use: critical, high, medium, low, info)", sevStr)
			}
			sel.MinSeverity = sev
		} else {
			sel.ScopeTags = append(sel.ScopeTags, p)
		}
	}

	return sel, nil
}

// Matches returns true if the control matches this selector.
// All scope tags must be present in the control's ScopeTags.
// If MinSeverity is set, the control's severity must meet or exceed it.
func (sel BuiltinSelector) Matches(ctl policy.ControlDefinition) bool {
	// Check severity first for a fast fail path.
	if sel.MinSeverity > policy.SeverityNone && !ctl.Severity.Gte(sel.MinSeverity) {
		return false
	}

	// Check scope tags: all selector tags must be present.
	for _, required := range sel.ScopeTags {
		matched := slices.ContainsFunc(ctl.ScopeTags, func(tag string) bool {
			return strings.EqualFold(tag, required)
		})
		if !matched {
			return false
		}
	}

	return true
}

// MatchesAny returns true if the control matches any of the given selectors.
func MatchesAny(ctl policy.ControlDefinition, selectors []BuiltinSelector) bool {
	if len(selectors) == 0 {
		return true // no selectors = include all
	}
	return slices.ContainsFunc(selectors, func(sel BuiltinSelector) bool {
		return sel.Matches(ctl)
	})
}
