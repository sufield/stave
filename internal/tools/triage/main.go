// Command triage answers "AWS launched feature X — does Stave need
// new controls?" by reading the botocore service model, filtering for
// security-relevant fields, and cross-referencing against the existing
// control catalog.
//
// Usage:
//
//	go run ./internal/tools/triage --service acm
//	go run ./internal/tools/triage --service acm --operation DescribeCertificate
//	go run ./internal/tools/triage --service acm --json
//	go run ./internal/tools/triage --service acm --fields-only
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/awsmeta"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/taxonomy"
)

func main() {
	service := flag.String("service", "", "AWS service name (e.g., acm, s3, bedrock)")
	operation := flag.String("operation", "", "filter to a specific operation (optional)")
	jsonOut := flag.Bool("json", false, "output as JSON")
	fieldsOnly := flag.Bool("fields-only", false, "show fields only, skip catalog cross-reference")
	flag.Parse()

	if *service == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./internal/tools/triage --service <name>")
		os.Exit(2)
	}

	initBotocoreDataDir()

	schema, err := awsmeta.ExtractSchema(*service)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if !schema.Available {
		fmt.Fprintf(os.Stderr, "SERVICE: %s\nSDK STATUS: not available (too new for botocore)\n", *service)
		os.Exit(0)
	}

	if *operation != "" {
		schema = filterOperation(schema, *operation)
	}

	secFields := filterSecurityRelevant(schema)

	if *fieldsOnly {
		if *jsonOut {
			writeJSON(TriageReport{
				ServiceName: schema.ServiceName,
				Available:   true,
				Operations:  secFields,
			})
		} else {
			writeFieldsOnly(schema.ServiceName, secFields)
		}
		return
	}

	catalog := loadCatalog()
	report := crossReference(schema.ServiceName, secFields, catalog)

	if *jsonOut {
		writeJSON(report)
	} else {
		writeReport(report)
	}
}

func filterOperation(schema *awsmeta.ServiceSchema, name string) *awsmeta.ServiceSchema {
	out := &awsmeta.ServiceSchema{
		ServiceName: schema.ServiceName,
		Available:   schema.Available,
	}
	for _, op := range schema.Operations {
		if strings.EqualFold(op.Name, name) {
			out.Operations = append(out.Operations, op)
		}
	}
	return out
}

func loadCatalog() *policy.Catalog {
	registry := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(), "embedded",
		ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()),
	)
	controls, err := registry.All()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load catalog: %v\n", err)
		os.Exit(1)
	}
	return policy.NewCatalog(controls)
}

func crossReference(serviceName string, secOps []SecurityOp, catalog *policy.Catalog) TriageReport {
	classifier := taxonomy.NewClassifier()

	serviceTag := normalizeServiceTag(serviceName)
	var existingControls []ExistingControl
	fieldSet := make(map[string]bool)

	for _, ctl := range catalog.List() {
		if !hasTag(ctl.ScopeTags, serviceTag) {
			continue
		}

		var fieldPaths []string
		ctl.UnsafePredicate.Walk(func(r policy.PredicateRule) {
			if !r.Field.IsZero() {
				fieldPaths = append(fieldPaths, r.Field.String())
			}
		})
		for _, p := range fieldPaths {
			fieldSet[p] = true
		}

		cats := classifier.ClassifyFields(
			string(ctl.ID), ctl.Name, ctl.Description, fieldPaths,
		)
		var catStrs []string
		for _, c := range cats {
			catStrs = append(catStrs, string(c))
		}

		existingControls = append(existingControls, ExistingControl{
			ID:         string(ctl.ID),
			Name:       ctl.Name,
			Categories: catStrs,
		})
	}

	var totalSec int
	var coveredFields []CoveredField
	var uncoveredFields []UncoveredField

	for _, sop := range secOps {
		for _, f := range sop.Fields {
			totalSec++
			if isCovered(f, fieldSet) {
				coveredFields = append(coveredFields, CoveredField{
					Operation: sop.Name,
					Field:     f,
				})
			} else {
				cats := classifier.Classify(f.Path)
				var catStrs []string
				for _, c := range cats {
					catStrs = append(catStrs, string(c))
				}
				uncoveredFields = append(uncoveredFields, UncoveredField{
					Operation:  sop.Name,
					Field:      f,
					Categories: catStrs,
				})
			}
		}
	}

	var coveragePct float64
	if totalSec > 0 {
		coveragePct = float64(len(coveredFields)) / float64(totalSec) * 100
	}

	return TriageReport{
		ServiceName:      serviceName,
		Available:        true,
		Operations:       secOps,
		ExistingControls: existingControls,
		TotalSecFields:   totalSec,
		CoveredFields:    coveredFields,
		UncoveredFields:  uncoveredFields,
		CoveragePct:      coveragePct,
	}
}

func isCovered(f awsmeta.Field, controlFields map[string]bool) bool {
	apiField := strings.ToLower(f.Path)
	derived := camelToSnake(f.Path)
	core := stripSuffixes(derived)
	apiConcepts := extractConcepts(derived)

	for path := range controlFields {
		lowerPath := strings.ToLower(path)
		seg := lastSegment(path)
		lowerSeg := strings.ToLower(seg)
		ctlCore := strings.TrimPrefix(lowerSeg, "has_")

		if strings.Contains(lowerPath, apiField) {
			return true
		}
		if strings.Contains(apiField, lowerSeg) {
			return true
		}
		if lowerSeg == derived || lowerSeg == "has_"+derived {
			return true
		}
		if ctlCore == derived || ctlCore == core {
			return true
		}
		if len(core) >= 4 && len(ctlCore) >= 4 {
			if strings.Contains(ctlCore, core) || strings.Contains(core, ctlCore) {
				return true
			}
		}
		ctlConcepts := extractConcepts(lowerPath)
		if conceptOverlap(apiConcepts, ctlConcepts) >= 1 {
			return true
		}
	}
	return false
}

func extractConcepts(path string) map[string]bool {
	concepts := make(map[string]bool)
	for seg := range strings.SplitSeq(path, ".") {
		for part := range strings.SplitSeq(seg, "_") {
			if len(part) >= 6 {
				concepts[part] = true
			}
		}
	}
	return concepts
}

func conceptOverlap(a, b map[string]bool) int {
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return n
}

func stripSuffixes(s string) string {
	for _, suf := range []string{"_id", "_arn", "_enabled", "_name"} {
		s = strings.TrimSuffix(s, suf)
	}
	return s
}

func camelToSnake(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				prev := runes[i-1]
				isUpper := prev >= 'A' && prev <= 'Z'
				nextIsLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
				if !isUpper || nextIsLower {
					b.WriteByte('_')
				}
			}
			b.WriteByte(byte(r - 'A' + 'a'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func lastSegment(path string) string {
	parts := strings.Split(path, ".")
	return parts[len(parts)-1]
}

func normalizeServiceTag(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "")
}

func hasTag(tags []kernel.ScopeTag, target string) bool {
	for _, t := range tags {
		if strings.EqualFold(string(t), target) {
			return true
		}
	}
	return false
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func initBotocoreDataDir() {
	if os.Getenv("BOTOCORE_DATA") != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "-c", //nolint:gosec // fixed command, not user input
		"import botocore; print(botocore.__path__[0]+'/data')").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot locate botocore: %v (set BOTOCORE_DATA env var)\n", err)
		os.Exit(1)
	}
	awsmeta.SetDataDir(strings.TrimSpace(string(out)))
}
