package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/awsmeta"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/taxonomy"
)

type botocoreEngine struct{}

func (e *botocoreEngine) Name() string { return "botocore" }

func (e *botocoreEngine) Run(ctx context.Context) (*EngineResult, error) {
	start := time.Now()

	catalog := loadCatalog()
	classifier := taxonomy.NewClassifier()

	serviceFieldSets := buildServiceFieldSets(catalog)
	awsServices := discoverAWSServices()

	var totalFields, coveredCount int
	var gaps []Gap

	for _, svc := range awsServices {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		schema, err := awsmeta.ExtractSchema(svc)
		if err != nil || !schema.Available {
			continue
		}

		fieldSet := serviceFieldSets[svc]

		for _, op := range schema.Operations {
			for _, f := range op.Fields {
				if !isSecurityRelevant(f.Path) {
					continue
				}
				totalFields++

				if isCoveredByControls(f, fieldSet) {
					coveredCount++
					continue
				}

				cats := classifier.Classify(f.Path)
				var catStrs []string
				for _, c := range cats {
					catStrs = append(catStrs, string(c))
				}

				gaps = append(gaps, Gap{
					Service:    svc,
					Property:   fmt.Sprintf("%s.%s", op.Name, f.Path),
					Severity:   "Medium",
					Taxonomy:   catStrs,
					Source:      "botocore",
					Confidence: "Medium",
				})
			}
		}
	}

	return &EngineResult{
		Engine:       "botocore",
		GapsFound:    gaps,
		Covered:      coveredCount,
		TotalChecked: totalFields,
		Duration:     time.Since(start),
		DataSource:   "botocore (system)",
	}, nil
}

func loadCatalog() *policy.Catalog {
	registry := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := registry.All()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: load catalog: %v\n", err)
		return policy.NewCatalog(nil)
	}
	return policy.NewCatalog(controls)
}

func buildServiceFieldSets(catalog *policy.Catalog) map[string]map[string]bool {
	sets := make(map[string]map[string]bool)
	for _, ctl := range catalog.List() {
		for _, tag := range ctl.ScopeTags {
			svc := strings.ReplaceAll(strings.ToLower(string(tag)), "-", "")
			if svc == "aws" {
				continue
			}
			if sets[svc] == nil {
				sets[svc] = make(map[string]bool)
			}
			ctl.UnsafePredicate.Walk(func(r policy.PredicateRule) {
				if !r.Field.IsZero() {
					sets[svc][r.Field.String()] = true
				}
			})
		}
	}
	return sets
}

func discoverAWSServices() []string {
	controlDir := "controls"
	entries, err := os.ReadDir(controlDir)
	if err != nil {
		return nil
	}
	var services []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		name := e.Name()
		if isNonAWSService(name) {
			continue
		}
		services = append(services, name)
	}
	return services
}

func isNonAWSService(name string) bool {
	switch name {
	case "azure", "gcp", "github", "cloudflare", "m365", "cisco", "vsphere",
		"compliance", "dataclass", "model", "dns", "exposure", "lifecycle", "guardrail":
		return true
	}
	return false
}

func isCoveredByControls(f awsmeta.Field, controlFields map[string]bool) bool {
	lower := strings.ToLower(f.Path)
	for path := range controlFields {
		if strings.Contains(strings.ToLower(path), lower) ||
			strings.Contains(lower, strings.ToLower(lastFieldSegment(path))) {
			return true
		}
	}
	return false
}

func lastFieldSegment(path string) string {
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
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

// discoverBotocoreServices returns AWS services that have botocore models.
// Used as fallback when control directory scanning finds nothing.
func discoverBotocoreServices() []string {
	out, err := awsmeta.ExtractSchema("s3")
	if err != nil || !out.Available {
		return nil
	}
	// Walk the botocore data directory
	dir := os.Getenv("BOTOCORE_DATA")
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var services []string
	for _, e := range entries {
		if e.IsDir() {
			services = append(services, e.Name())
		}
	}
	return services
}

