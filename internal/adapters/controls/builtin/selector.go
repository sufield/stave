// Package builtin provides embedded control definitions compiled into the binary.
package builtin

import (
	"errors"
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
		return Selector{}, errors.New("empty selector")
	}

	sel := Selector{}
	rest := s
	for rest != "" {
		var p string
		p, rest, _ = strings.Cut(rest, "/")
		trimmedP := strings.TrimSpace(p)
		if trimmedP == "" {
			continue
		}
		if len(trimmedP) >= 9 && strings.EqualFold(trimmedP[:9], "severity:") {
			sevStr := strings.TrimSuffix(trimmedP[9:], "+")
			sev, err := policy.ParseSeverity(sevStr)
			if err != nil || sev == policy.SeverityNone {
				return Selector{}, fmt.Errorf("invalid severity %q (use: critical, high, medium, low, info)", sevStr)
			}
			sel.MinSeverity = sev
		} else {
			needsLower := false
			for i := 0; i < len(trimmedP); i++ {
				if trimmedP[i] >= 'A' && trimmedP[i] <= 'Z' {
					needsLower = true
					break
				}
			}
			if needsLower {
				sel.Tags = append(sel.Tags, strings.ToLower(trimmedP))
			} else {
				sel.Tags = append(sel.Tags, trimmedP)
			}
		}
	}

	return sel, nil
}

// Matches returns true if the control satisfies all selector criteria.
// All tags must be present in the control's ScopeTags (case-insensitive).
// If MinSeverity is set, the control's severity must meet or exceed it.
func (sel Selector) Matches(ctl *policy.ControlDefinition) bool {
	// Check severity first for a fast fail path.
	if sel.MinSeverity.IsSet() && !ctl.Severity.Gte(sel.MinSeverity) {
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
func MatchesAny(ctl *policy.ControlDefinition, selectors []Selector) bool {
	if len(selectors) == 0 {
		return true // no selectors = include all
	}
	return slices.ContainsFunc(selectors, func(sel Selector) bool {
		return sel.Matches(ctl)
	})
}
