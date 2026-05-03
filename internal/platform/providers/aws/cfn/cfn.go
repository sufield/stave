// Package cfn ships the CloudFormation-specific data tables Stave
// controls consult when evaluating templates. Currently exposes the
// sensitive-parameter-name pattern catalog used by
// CTL.CFN.PARAM.NOECHO.001.
package cfn

import (
	_ "embed"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed sensitive_param_names.yaml
var sensitiveParamNamesYAML []byte

type sensitiveParamNamesDoc struct {
	Patterns []string `yaml:"sensitive_param_name_patterns"`
}

var (
	patternsOnce sync.Once
	patterns     []string
	errPatterns  error
)

func loadPatterns() {
	var doc sensitiveParamNamesDoc
	if err := yaml.Unmarshal(sensitiveParamNamesYAML, &doc); err != nil {
		errPatterns = fmt.Errorf("cfn: parse sensitive_param_names.yaml: %w", err)
		return
	}
	patterns = doc.Patterns
}

// SensitiveParamPatterns returns the case-insensitive substring
// patterns CTL.CFN.PARAM.NOECHO.001 uses to flag CloudFormation
// parameters that should carry NoEcho: true. The slice is built
// once from the embedded YAML; callers MUST treat it as read-only.
//
// Returns a nil slice on parse failure (which would only fire if
// the embedded YAML were corrupted at build time); callers that
// need to surface the parse error should call SensitiveParamPatternsE.
func SensitiveParamPatterns() []string {
	patternsOnce.Do(loadPatterns)
	return patterns
}

// SensitiveParamPatternsE returns the patterns alongside any
// parse error. Provided so callers (linters, CLI doctor) can
// surface a structural problem in the embedded data instead of
// silently degrading to an empty pattern list.
func SensitiveParamPatternsE() ([]string, error) {
	patternsOnce.Do(loadPatterns)
	return patterns, errPatterns
}
