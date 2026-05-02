package exemption

import (
	"fmt"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// yamlExemptionConfig is the YAML wire-format for policy.ExemptionConfig.
type yamlExemptionConfig struct {
	Version string              `yaml:"version"`
	Assets  []yamlExemptionRule `yaml:"assets"`
}

// yamlExemptionRule is the YAML wire-format for policy.ExemptionRule.
type yamlExemptionRule struct {
	Pattern string `yaml:"pattern"`
	Reason  string `yaml:"reason"`
}

// exemptionConfigToDomain converts a parsed YAML exemption document
// to the domain ExemptionConfig.
//
// Rules with an empty Pattern or Reason are rejected: a missing
// Pattern matches every asset (a silent global suppression), and a
// missing Reason erases the audit trail an exemption is supposed
// to provide. Both are footguns the YAML loader used to accept and
// pass through to the engine, where the silent-match case produced
// reports that "no findings exist anywhere" without naming the
// exemption that did the suppressing.
func exemptionConfigToDomain(y yamlExemptionConfig) (*policy.ExemptionConfig, error) {
	var invalid []string
	rules := make([]policy.ExemptionRule, len(y.Assets))
	for i, r := range y.Assets {
		if strings.TrimSpace(r.Pattern) == "" {
			invalid = append(invalid, fmt.Sprintf("rule %d: empty Pattern", i))
		}
		if strings.TrimSpace(r.Reason) == "" {
			invalid = append(invalid, fmt.Sprintf("rule %d: empty Reason", i))
		}
		rules[i] = policy.ExemptionRule{
			Pattern: r.Pattern,
			Reason:  r.Reason,
		}
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("invalid exemption rules: %s", strings.Join(invalid, "; "))
	}
	return policy.NewExemptionConfig(y.Version, rules), nil
}
