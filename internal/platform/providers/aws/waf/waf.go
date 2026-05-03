// Package waf ships the WAFv2-specific data tables Stave controls
// consult. Currently exposes the required-rule-group catalog used
// by WAF coverage controls.
package waf

import (
	_ "embed"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed required_rule_groups.yaml
var requiredRuleGroupsYAML []byte

// RuleGroup describes a single managed rule group required by
// Stave coverage controls. OWASP categories list the OWASP-Top-10
// IDs the group covers (e.g. "A03", "A05") so coverage reports
// can surface which categories a WAFv2 deployment satisfies.
type RuleGroup struct {
	Name            string   `yaml:"name"`
	Description     string   `yaml:"description"`
	OWASPCategories []string `yaml:"owasp_categories"`
}

type requiredRuleGroupsDoc struct {
	Version string      `yaml:"version"`
	Groups  []RuleGroup `yaml:"required_groups"`
}

var (
	groupsOnce sync.Once
	groups     []RuleGroup
	errGroups  error
)

func loadGroups() {
	var doc requiredRuleGroupsDoc
	if err := yaml.Unmarshal(requiredRuleGroupsYAML, &doc); err != nil {
		errGroups = fmt.Errorf("waf: parse required_rule_groups.yaml: %w", err)
		return
	}
	groups = doc.Groups
}

// RequiredRuleGroups returns the names of the WAFv2 managed rule
// groups Stave coverage controls expect every WAF deployment to
// include. Returns a flat []string so callers performing a simple
// presence check don't have to reach for the typed catalog.
func RequiredRuleGroups() []string {
	groupsOnce.Do(loadGroups)
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.Name
	}
	return out
}

// RequiredRuleGroupCatalog returns the typed RuleGroup entries
// (name + description + OWASP categories). Callers that render
// coverage reports use this; presence-only callers prefer
// RequiredRuleGroups.
func RequiredRuleGroupCatalog() []RuleGroup {
	groupsOnce.Do(loadGroups)
	return groups
}

// RequiredRuleGroupsE returns the names alongside any parse
// error. See cfn.SensitiveParamPatternsE for the rationale.
func RequiredRuleGroupsE() ([]string, error) {
	groupsOnce.Do(loadGroups)
	if errGroups != nil {
		return nil, errGroups
	}
	return RequiredRuleGroups(), nil
}
