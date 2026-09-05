// Command csl validates a Control Specification Language (CSL) spec
// against the JSON Schema and cross-checks with the existing catalog.
//
// Usage:
//
//	go run ./internal/tools/csl validate --spec spec.yaml
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sufield/stave/internal/collectorcontract"
	"github.com/sufield/stave/internal/controldata"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

var idPattern = regexp.MustCompile(`^CTL\.[A-Z0-9]+\.[A-Z0-9.]+\.\d{3}$`)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: csl validate --spec <file.yaml>")
		os.Exit(2)
	}

	specPath := ""
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--spec" && i+1 < len(os.Args) {
			specPath = os.Args[i+1]
			i++
		}
	}
	if specPath == "" {
		fmt.Fprintln(os.Stderr, "error: --spec is required")
		os.Exit(2)
	}

	if err := run(specPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type issue struct {
	check   string
	message string
}

func run(specPath string) error {
	raw, err := fsutil.ReadFileLimited(specPath)
	if err != nil {
		return fmt.Errorf("read spec: %w", err)
	}

	// Parse YAML into generic map for JSON Schema validation.
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse YAML: %w", err)
	}
	doc = normalizeYAML(doc)

	// Also parse into a typed struct for cross-checks.
	var spec cslSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("parse spec: %w", err)
	}

	var issues []issue

	// 1. Schema compliance
	if schemaIssues := validateSchema(doc); len(schemaIssues) > 0 {
		issues = append(issues, schemaIssues...)
	}

	// 2. ID convention
	if !idPattern.MatchString(spec.Spec.ID) {
		issues = append(issues, issue{
			check:   "id-convention",
			message: fmt.Sprintf("ID %q does not match CTL.<SERVICE>.<CATEGORY>.<SHORTNAME>.<NNN>", spec.Spec.ID),
		})
	}

	// 3. Duplicate ID check
	if spec.Spec.ID != "" {
		if dup := checkDuplicateID(spec.Spec.ID); dup != "" {
			issues = append(issues, issue{
				check:   "duplicate-id",
				message: fmt.Sprintf("control ID %q already exists at %s", spec.Spec.ID, dup),
			})
		}
	}

	// 4. Severity present
	validSeverities := map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	if !validSeverities[spec.Spec.Severity] {
		issues = append(issues, issue{
			check:   "severity",
			message: fmt.Sprintf("severity %q is not one of critical, high, medium, low", spec.Spec.Severity),
		})
	}

	// 5. Differentiation thesis required for compound controls
	if spec.Spec.ScopeConstraint != nil && spec.Spec.ScopeConstraint.MinResources > 1 {
		if spec.Spec.DifferentiationThesis == nil {
			issues = append(issues, issue{
				check:   "differentiation-thesis",
				message: "scope_constraint.min_resources > 1 requires differentiation_thesis",
			})
		}
	}

	// 6. Condition operator/value consistency
	for _, pair := range []struct {
		label string
		cond  *condition
	}{
		{"unsafe_condition", spec.Spec.UnsafeCondition},
		{"safe_condition", spec.Spec.SafeCondition},
	} {
		if pair.cond == nil {
			continue
		}
		if condIssues := validateCondition(pair.label, pair.cond); len(condIssues) > 0 {
			issues = append(issues, condIssues...)
		}
	}

	// 7. Contract field cross-check (WARN only)
	var warnings []issue
	if spec.Spec.DataReadiness != nil && len(spec.Spec.DataReadiness.FieldsRequired) > 0 {
		warnings = checkContractFields(spec.Spec.DataReadiness.FieldsRequired)
	}

	// Report
	if len(issues) > 0 {
		fmt.Fprintf(os.Stderr, "CSL spec %s: %d issue(s)\n\n", specPath, len(issues))
		for _, iss := range issues {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", iss.check, iss.message)
		}
		return fmt.Errorf("%d validation issue(s)", len(issues))
	}

	fmt.Printf("CSL spec %s: valid\n", specPath)
	fmt.Printf("  id:         %s\n", spec.Spec.ID)
	fmt.Printf("  service:    %s\n", spec.Spec.Service)
	fmt.Printf("  asset_type: %s\n", spec.Spec.AssetType)
	fmt.Printf("  severity:   %s\n", spec.Spec.Severity)
	fmt.Printf("  threat:     %s\n", spec.Spec.Threat)

	if len(warnings) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d warning(s):\n", len(warnings))
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "  [%s] %s\n", w.check, w.message)
		}
	}
	return nil
}

func validateSchema(doc any) []issue {
	schemaBytes, err := os.ReadFile("data/schemas/csl-spec.schema.json")
	if err != nil {
		return []issue{{check: "schema", message: fmt.Sprintf("load schema: %v", err)}}
	}
	var schemaDef any
	if err := json.Unmarshal(schemaBytes, &schemaDef); err != nil {
		return []issue{{check: "schema", message: fmt.Sprintf("parse schema: %v", err)}}
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("csl-spec.schema.json", schemaDef); err != nil {
		return []issue{{check: "schema", message: fmt.Sprintf("add schema resource: %v", err)}}
	}

	schema, err := compiler.Compile("csl-spec.schema.json")
	if err != nil {
		return []issue{{check: "schema", message: fmt.Sprintf("compile schema: %v", err)}}
	}

	if err := schema.Validate(doc); err != nil {
		if vErr, ok := errors.AsType[*jsonschema.ValidationError](err); ok {
			return flattenValidationErrors(vErr)
		}
		return []issue{{check: "schema", message: err.Error()}}
	}
	return nil
}

func flattenValidationErrors(vErr *jsonschema.ValidationError) []issue {
	var issues []issue
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if e.ErrorKind != nil {
			path := "/" + strings.Join(e.InstanceLocation, "/")
			issues = append(issues, issue{
				check:   "schema",
				message: fmt.Sprintf("%s: %s", path, e.Error()),
			})
		}
		for _, cause := range e.Causes {
			walk(cause)
		}
	}
	walk(vErr)
	if len(issues) == 0 {
		issues = append(issues, issue{check: "schema", message: vErr.Error()})
	}
	return issues
}

func checkDuplicateID(id string) string {
	embeddedFS := controldata.FS
	var found string
	_ = fs.WalkDir(embeddedFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, readErr := fs.ReadFile(embeddedFS, path)
		if readErr != nil {
			return nil
		}
		var stub struct {
			ID string `yaml:"id"`
		}
		if yaml.Unmarshal(data, &stub) == nil && stub.ID == id {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeYAML(vv)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalizeYAML(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = normalizeYAML(x[i])
		}
		return out
	default:
		return v
	}
}

func validateCondition(label string, cond *condition) []issue {
	var issues []issue

	if cond.Field == "" {
		issues = append(issues, issue{
			check:   "condition-syntax",
			message: fmt.Sprintf("%s: field is empty", label),
		})
	}

	switch cond.Operator {
	case "in", "not_in":
		if _, ok := cond.Value.([]any); !ok {
			issues = append(issues, issue{
				check:   "condition-syntax",
				message: fmt.Sprintf("%s: operator %q requires a list value, got %T", label, cond.Operator, cond.Value),
			})
		}
	case "gt", "gte", "lt", "lte":
		switch cond.Value.(type) {
		case int, float64:
		default:
			issues = append(issues, issue{
				check:   "condition-syntax",
				message: fmt.Sprintf("%s: operator %q requires a numeric value, got %T", label, cond.Operator, cond.Value),
			})
		}
	case "prefix", "suffix":
		if _, ok := cond.Value.(string); !ok {
			issues = append(issues, issue{
				check:   "condition-syntax",
				message: fmt.Sprintf("%s: operator %q requires a string value, got %T", label, cond.Operator, cond.Value),
			})
		}
	case "regex":
		s, ok := cond.Value.(string)
		if !ok {
			issues = append(issues, issue{
				check:   "condition-syntax",
				message: fmt.Sprintf("%s: operator %q requires a string value, got %T", label, cond.Operator, cond.Value),
			})
		} else if _, err := regexp.Compile(s); err != nil {
			issues = append(issues, issue{
				check:   "condition-syntax",
				message: fmt.Sprintf("%s: invalid regex %q: %v", label, s, err),
			})
		}
	case "missing", "present", "eq", "ne", "any_match", "all_match":
		// These accept any value type.
	default:
		issues = append(issues, issue{
			check:   "condition-syntax",
			message: fmt.Sprintf("%s: unknown operator %q", label, cond.Operator),
		})
	}
	return issues
}

func checkContractFields(fieldsRequired []string) []issue {
	contract, err := collectorcontract.Load()
	if err != nil {
		return []issue{{check: "contract-crosscheck", message: fmt.Sprintf("load contract: %v", err)}}
	}
	idx := contract.FieldIndex()

	var warnings []issue
	for _, f := range fieldsRequired {
		if _, ok := idx[f]; !ok {
			warnings = append(warnings, issue{
				check:   "contract-crosscheck",
				message: fmt.Sprintf("field %q not found in collector contract — may be planned or use a different path", f),
			})
		}
	}
	return warnings
}

type cslSpec struct {
	Spec struct {
		ID                    string            `yaml:"id"`
		Service               string            `yaml:"service"`
		AssetType             string            `yaml:"asset_type"`
		Threat                string            `yaml:"threat"`
		AttackStage           string            `yaml:"attack_stage"`
		Severity              string            `yaml:"severity"`
		UnsafeCondition       *condition        `yaml:"unsafe_condition"`
		SafeCondition         *condition        `yaml:"safe_condition"`
		DetectionDependency   *string           `yaml:"detection_dependency"`
		Invariant             string            `yaml:"invariant"`
		ScopeConstraint       *scopeConstraint  `yaml:"scope_constraint"`
		DifferentiationThesis *diffThesis       `yaml:"differentiation_thesis"`
		References            map[string]string `yaml:"references"`
		DataReadiness         *dataReadiness    `yaml:"data_readiness"`
	} `yaml:"spec"`
}

type condition struct {
	Field    string `yaml:"field"`
	Operator string `yaml:"operator"`
	Value    any    `yaml:"value"`
}

type scopeConstraint struct {
	MinResources  int      `yaml:"min_resources"`
	ResourceTypes []string `yaml:"resource_types"`
	Thesis        string   `yaml:"thesis"`
}

type diffThesis struct {
	ScannerGap  string `yaml:"scanner_gap"`
	Positioning string `yaml:"positioning"`
	ArticleHook string `yaml:"article_hook"`
}

type dataReadiness struct {
	FieldsRequired  []string `yaml:"fields_required"`
	FieldsAvailable []string `yaml:"fields_available"`
	FieldsMissing   []string `yaml:"fields_missing"`
}
