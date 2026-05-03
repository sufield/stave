// Package ssm ships the SSM Parameter Store-specific data tables
// Stave controls consult. Currently exposes the sensitive-path
// prefix catalog used by CTL.SSM.SECURETYPE.001.
package ssm

import (
	_ "embed"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed sensitive_paths.yaml
var sensitivePathsYAML []byte

type sensitivePathsDoc struct {
	Prefixes []string `yaml:"sensitive_path_prefixes"`
}

var (
	prefixesOnce sync.Once
	prefixes     []string
	errPrefixes  error
)

func loadPrefixes() {
	var doc sensitivePathsDoc
	if err := yaml.Unmarshal(sensitivePathsYAML, &doc); err != nil {
		errPrefixes = fmt.Errorf("ssm: parse sensitive_paths.yaml: %w", err)
		return
	}
	prefixes = doc.Prefixes
}

// SensitivePathPrefixes returns the path-segment prefixes
// CTL.SSM.SECURETYPE.001 uses to classify SSM parameters whose
// path indicates they hold sensitive data and must use the
// SecureString type. Callers MUST treat the returned slice as
// read-only.
func SensitivePathPrefixes() []string {
	prefixesOnce.Do(loadPrefixes)
	return prefixes
}

// SensitivePathPrefixesE returns the prefixes alongside any parse
// error. See cfn.SensitiveParamPatternsE for the rationale.
func SensitivePathPrefixesE() ([]string, error) {
	prefixesOnce.Do(loadPrefixes)
	return prefixes, errPrefixes
}
