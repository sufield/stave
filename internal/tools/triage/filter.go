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

var excludePatterns = []string{
	"nexttoken", "marker", "istruncated", "maxresults", "maxitems",
	"secretstring", "secretbinary", "randompassword",
	"versionid", "versionstages", "versionidstostages",
	"secretlist", "versions",
	"requestid", "responsemetadata",
	"updatetoken", "sourcemetadata",
	"continuationtoken", "nextcontinuationtoken",
	"maxkeys", "keycount", "maxitems",
	"errordocument", "metadata",
}

var excludeOpPrefixes = []string{
	"GetSecretValue", "GetRandomPassword",
	"PutSecretValue", "UpdateSecretVersionStage",
	"GetObject", "PutObject", "HeadObject",
	"ListObjects", "ListObjectsV2", "ListObjectVersions",
	"ListParts", "ListMultipartUploads",
	"ListBucketAnalyticsConfigurations",
	"ListBucketIntelligentTieringConfigurations",
	"ListBucketInventoryConfigurations",
	"ListBucketMetricsConfigurations",
	"ListDirectoryBuckets",
}

type SecurityOp struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Fields []awsmeta.Field `json:"fields"`
}

func filterSecurityRelevant(schema *awsmeta.ServiceSchema) []SecurityOp {
	var result []SecurityOp
	for _, op := range schema.Operations {
		if isExcludedOp(op.Name) {
			continue
		}
		var secFields []awsmeta.Field
		for _, f := range op.Fields {
			if isSecurityRelevant(f.Path) && !isExcludedField(f.Path) {
				secFields = append(secFields, f)
			}
		}
		secFields = collapseStructChildren(secFields)
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

func collapseStructChildren(fields []awsmeta.Field) []awsmeta.Field {
	parents := make(map[string]bool)
	for _, f := range fields {
		if f.Kind == "structure" {
			parents[f.Path+"."] = true
		}
	}
	if len(parents) == 0 {
		return fields
	}
	var result []awsmeta.Field
	for _, f := range fields {
		isChild := false
		for prefix := range parents {
			if strings.HasPrefix(f.Path, prefix) {
				isChild = true
				break
			}
		}
		if !isChild {
			result = append(result, f)
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

func isExcludedField(path string) bool {
	lower := strings.ToLower(path)
	for _, ex := range excludePatterns {
		if strings.Contains(lower, ex) {
			return true
		}
	}
	if strings.HasSuffix(lower, ".tag.key") || strings.HasSuffix(lower, ".tag.value") {
		return true
	}
	return false
}

func isExcludedOp(name string) bool {
	for _, prefix := range excludeOpPrefixes {
		if strings.EqualFold(name, prefix) {
			return true
		}
	}
	return false
}
