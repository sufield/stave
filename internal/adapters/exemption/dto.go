package exemption

import policy "github.com/sufield/stave/internal/core/controldef"

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

func exemptionConfigToDomain(y yamlExemptionConfig) *policy.ExemptionConfig {
	rules := make([]policy.ExemptionRule, len(y.Assets))
	for i, r := range y.Assets {
		rules[i] = policy.ExemptionRule{
			Pattern: r.Pattern,
			Reason:  r.Reason,
		}
	}
	return policy.NewExemptionConfig(y.Version, rules)
}
