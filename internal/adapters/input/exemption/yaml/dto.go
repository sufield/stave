package yaml

import "github.com/sufield/stave/internal/domain/policy"

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

func exemptionConfigToDomain(y yamlExemptionConfig) policy.ExemptionConfig {
	rules := make([]policy.ExemptionRule, len(y.Assets))
	for i, r := range y.Assets {
		rules[i] = policy.ExemptionRule{
			Pattern: r.Pattern,
			Reason:  r.Reason,
		}
	}
	return policy.ExemptionConfig{
		Version: y.Version,
		Assets:  rules,
	}
}
