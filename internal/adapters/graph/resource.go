package graph

import (
	"strings"
)

// resourceClassRules maps provider_type tokens to resource_class.
// Evaluated in order — first match wins. Use a slice (not a map)
// for deterministic iteration and to avoid substring collisions
// (e.g. "ecr" inside "secretsmanager").
// Source: docs/ontology/resource-classes.json
//
// Compound rule keys (those containing an underscore — virtual_machine,
// compute_engine, security_group, key_vault, service_bus, front_door)
// intentionally rely on the substring fallback below: ToResourceClass
// first attempts exact-token matching against the underscore-split
// tokens; only the substring pass can match a multi-token key like
// `virtual_machine` against an input like `azure_virtual_machine_scale_set`.
// Splitting them into single-token rules would let `virtual` or
// `service` match unrelated tokens (e.g. `serviceaccount` -> queue),
// so the compound form is preserved and resolved via fallback.
var resourceClassRules = []struct {
	key   string
	class string
}{
	{"s3", "storage"},
	{"storage", "storage"},
	{"blob", "storage"},
	{"backup", "storage"},

	{"rds", "database"},
	{"dynamodb", "database"},
	{"database", "database"},
	{"cosmos", "database"},
	{"sql", "database"},
	{"spanner", "database"},

	{"lambda", "compute"},
	{"function", "compute"},

	{"ec2", "instance"},
	{"virtual_machine", "instance"},
	{"compute_engine", "instance"},

	{"ecs", "container"},
	{"eks", "container"},
	{"aks", "container"},
	{"gke", "container"},
	{"container", "container"},

	{"vpc", "network"},
	{"security_group", "network"},
	{"sg", "network"},
	{"nacl", "network"},
	{"subnet", "network"},
	{"vnet", "network"},
	{"nsg", "network"},
	{"firewall", "network"},
	{"apigateway", "network"},

	{"iam", "identity"},
	{"cognito", "identity"},

	{"kms", "key"},
	{"key_vault", "key"},

	{"secret", "secret"},

	{"cloudfront", "cdn"},
	{"front_door", "cdn"},

	{"route53", "dns"},
	{"dns", "dns"},

	{"ecr", "registry"},
	{"acr", "registry"},
	{"artifact", "registry"},

	{"sqs", "queue"},
	{"sns", "queue"},
	{"service_bus", "queue"},
	{"pubsub", "queue"},

	{"cloudtrail", "log"},
	{"cloudwatch", "log"},
	{"config", "log"},
	{"guardduty", "log"},
	{"monitor", "log"},
}

// ToResourceClass maps a provider_type (e.g. "aws_s3_bucket") to a
// provider-agnostic resource class (e.g. "storage").
func ToResourceClass(providerType string) string {
	lower := strings.ToLower(providerType)

	// Strip common prefixes.
	for _, prefix := range []string{"aws_", "azure_", "gcp_"} {
		lower = strings.TrimPrefix(lower, prefix)
	}

	// Token match first — split on _ and match whole tokens to avoid
	// substring collisions (e.g. "ecr" inside "secretsmanager").
	for _, rule := range resourceClassRules {
		if hasToken(lower, rule.key) {
			return rule.class
		}
	}

	// Fallback: substring match in deterministic order.
	for _, rule := range resourceClassRules {
		if strings.Contains(lower, rule.key) {
			return rule.class
		}
	}

	return "unknown"
}

func hasToken(s, token string) bool {
	rest := s
	for rest != "" {
		var part string
		part, rest, _ = strings.Cut(rest, "_")
		if part == token {
			return true
		}
	}
	return false
}
