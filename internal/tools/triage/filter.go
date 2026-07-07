package main

import (
	"strings"

	"github.com/sufield/stave/internal/adapters/awsmeta"
)

var securityKeywords = []string{
	"encrypt", "kms", "public", "policy", "logging", "log",
	"auth", "mfa", "ssl", "tls", "vpc", "subnet", "security",
	"access", "rotation", "backup", "deletion", "protect",
	"version", "scan", "monitor", "role", "principal",
	"permission", "boundary", "token", "credential",
	"session", "duration", "internet", "ingress", "egress",
	"isolation", "privileged", "root", "metadata",
	"scope", "wildcard", "domain", "acme",
	"secret", "password", "key", "certificate", "cert",
	"audit", "trail", "guardduty", "inspector",
	"private", "endpoint",
}

// SecurityOp groups security-relevant fields by operation.
type SecurityOp struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Fields []awsmeta.Field `json:"fields"`
}

func filterSecurityRelevant(schema *awsmeta.ServiceSchema) []SecurityOp {
	var result []SecurityOp
	for _, op := range schema.Operations {
		var secFields []awsmeta.Field
		for _, f := range op.Fields {
			if isSecurityRelevant(f.Path) {
				secFields = append(secFields, f)
			}
		}
		if len(secFields) > 0 {
			result = append(result, SecurityOp{
				Name:   op.Name,
				Type:   op.Type,
				Fields: secFields,
			})
		}
	}
	return result
}

func isSecurityRelevant(path string) bool {
	lower := strings.ToLower(path)
	for _, kw := range securityKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
