package graph

import "strings"

// resourceClassMap maps provider_type substrings to resource_class.
// Source: docs/ontology/resource-classes.json
var resourceClassMap = map[string]string{
	"s3":              "storage",
	"storage":         "storage",
	"blob":            "storage",
	"rds":             "database",
	"dynamodb":        "database",
	"database":        "database",
	"cosmos":          "database",
	"sql":             "database",
	"spanner":         "database",
	"lambda":          "compute",
	"function":        "compute",
	"ec2":             "instance",
	"virtual_machine": "instance",
	"compute_engine":  "instance",
	"ecs":             "container",
	"eks":             "container",
	"aks":             "container",
	"gke":             "container",
	"container":       "container",
	"vpc":             "network",
	"sg":              "network",
	"security_group":  "network",
	"nacl":            "network",
	"subnet":          "network",
	"vnet":            "network",
	"nsg":             "network",
	"firewall":        "network",
	"iam":             "identity",
	"kms":             "key",
	"key_vault":       "key",
	"secret":          "secret",
	"cloudfront":      "cdn",
	"front_door":      "cdn",
	"route53":         "dns",
	"dns":             "dns",
	"ecr":             "registry",
	"acr":             "registry",
	"artifact":        "registry",
	"sqs":             "queue",
	"sns":             "queue",
	"service_bus":     "queue",
	"pubsub":          "queue",
	"cloudtrail":      "log",
	"cloudwatch":      "log",
	"config":          "log",
	"guardduty":       "log",
	"monitor":         "log",
	"cognito":         "identity",
	"apigateway":      "network",
	"backup":          "storage",
}

// ToResourceClass maps a provider_type (e.g. "aws_s3_bucket") to a
// provider-agnostic resource class (e.g. "storage").
func ToResourceClass(providerType string) string {
	lower := strings.ToLower(providerType)

	// Strip common prefixes.
	for _, prefix := range []string{"aws_", "azure_", "gcp_"} {
		lower = strings.TrimPrefix(lower, prefix)
	}

	// Try exact match first, then substring match.
	for key, class := range resourceClassMap {
		if strings.Contains(lower, key) {
			return class
		}
	}
	return "unknown"
}
