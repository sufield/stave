// Command gencontrol scaffolds a new security control with E2E test fixtures.
//
// It generates a complete policy bundle:
//  1. A ctrl.v1 YAML control definition (validated at generation time)
//  2. A fail fixture: two observation snapshots where the asset is unsafe
//  3. A pass fixture: two observation snapshots where the asset is compliant
//  4. E2E metadata (args.txt, expected.exit, expected.findings.count)
//
// Usage:
//
//	go run ./internal/tools/gencontrol \
//	  --id CTL.IAM.CONSOLE.MFA.001 \
//	  --name "Console Users Must Have MFA Enabled" \
//	  --domain identity \
//	  --severity high \
//	  --scope-tags aws,iam \
//	  --asset-type aws_iam_user \
//	  --kind user \
//	  --kind-field properties.identity.kind \
//	  --field properties.identity.console_access.mfa_enabled \
//	  --op eq \
//	  --value false \
//	  --remediation "Enable MFA for the user via IAM > Users > Security credentials > MFA."
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/yamlutil"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.ID, "id", "", "Control ID (e.g., CTL.S3.PUBLIC.001) (required)")
	flag.StringVar(&cfg.Name, "name", "", "Control name (required)")
	flag.StringVar(&cfg.Domain, "domain", "exposure", "Domain label (exposure, identity, governance)")
	flag.StringVar(&cfg.Severity, "severity", "high", "Severity (critical, high, medium, low, info)")
	flag.StringVar(&cfg.ScopeTags, "scope-tags", "aws,s3", "Comma-separated scope tags")
	flag.StringVar(&cfg.AssetType, "asset-type", "aws_s3_bucket", "Asset type for test fixtures")
	flag.StringVar(&cfg.Kind, "kind", "", "Asset kind filter (e.g., bucket, user, account, password_policy)")
	flag.StringVar(&cfg.KindField, "kind-field", "", "Field path for kind check (default: auto from domain)")
	flag.StringVar(&cfg.Field, "field", "", "Predicate field path (e.g., properties.storage.access.public_read) (required)")
	flag.StringVar(&cfg.Op, "op", "eq", "Predicate operator (eq, ne, lt, gt, missing, present)")
	flag.StringVar(&cfg.Value, "value", "true", "Unsafe value (true, false, or a number/string)")
	flag.StringVar(&cfg.SafeValue, "safe-value", "", "Safe value for compliant snapshot (default: inverse of --value)")
	flag.StringVar(&cfg.Description, "description", "", "Control description (auto-generated if empty)")
	flag.StringVar(&cfg.Remediation, "remediation", "", "Remediation action text (required)")
	flag.StringVar(&cfg.OutDir, "out", "", "Output base directory (default: testdata/e2e/)")
	flag.StringVar(&cfg.Compliance, "compliance", "", "Compliance refs as key=value pairs (e.g., cis_aws_v1.4.0=1.5,hipaa=164.312(d))")
	flag.Parse()

	cfg.Stdout = os.Stdout

	if err := cfg.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	ID          string
	Name        string
	Domain      string
	Severity    string
	ScopeTags   string
	AssetType   string
	Kind        string
	KindField   string
	Field       string
	Op          string
	Value       string
	SafeValue   string
	Description string
	Remediation string
	OutDir      string
	Compliance  string
	Stdout      io.Writer // diagnostic output; defaults to os.Stdout
}

var (
	validDomains    = map[string]struct{}{"exposure": {}, "identity": {}, "governance": {}}
	validSeverities = map[string]struct{}{"critical": {}, "high": {}, "medium": {}, "low": {}, "info": {}}
	validOps        = map[string]struct{}{"eq": {}, "ne": {}, "lt": {}, "gt": {}, "missing": {}, "present": {}}
)

func (c *config) validate() error {
	if c.ID == "" {
		return errors.New("--id is required")
	}
	if err := fsutil.SafeFilename(c.ID); err != nil {
		return fmt.Errorf("--id: %w", err)
	}
	if c.Name == "" {
		return errors.New("--name is required")
	}
	if c.Field == "" {
		return errors.New("--field is required")
	}
	if c.Remediation == "" {
		return errors.New("--remediation is required (every control must have a remediation path)")
	}
	if _, ok := validDomains[c.Domain]; !ok {
		return errors.New("--domain: must be one of exposure, identity, governance")
	}
	if _, ok := validSeverities[c.Severity]; !ok {
		return errors.New("--severity: must be one of critical, high, medium, low, info")
	}
	if _, ok := validOps[c.Op]; !ok {
		return errors.New("--op: must be one of eq, ne, lt, gt, missing, present")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot determine working directory: %w", err)
	}
	if _, err := fsutil.SafeDir(c.OutDir, cwd); err != nil {
		return fmt.Errorf("--out: %w", err)
	}
	return nil
}

func run(cfg config) error {
	if cfg.SafeValue == "" {
		cfg.SafeValue = invertValue(cfg.Value)
	}
	if cfg.Description == "" {
		cfg.Description = fmt.Sprintf("Detects assets where %s is %s %s.", shortField(cfg.Field), cfg.Op, cfg.Value)
	}
	if cfg.Kind != "" && cfg.KindField == "" {
		cfg.KindField = defaultKindField(cfg.Domain)
	}

	data := templateData{
		ID:          cfg.ID,
		Name:        cfg.Name,
		Domain:      cfg.Domain,
		Severity:    cfg.Severity,
		ScopeTags:   strings.Split(cfg.ScopeTags, ","),
		Kind:        cfg.Kind,
		KindField:   cfg.KindField,
		Field:       cfg.Field,
		Op:          cfg.Op,
		Value:       typedValue(cfg.Value),
		Description: sanitizeScalar(cfg.Description),
		Remediation: sanitizeScalar(cfg.Remediation),
		Compliance:  parseCompliance(cfg.Compliance),
	}

	baseDir := cfg.OutDir
	if baseDir == "" {
		baseDir = "testdata/e2e"
	}
	failDir := filepath.Join(baseDir, defaultFixtureName(cfg.ID, "fail"))
	passDir := filepath.Join(baseDir, defaultFixtureName(cfg.ID, "pass"))

	// ── Control YAML ─────────────────────────────────────────
	controlYAML, err := renderTemplate(controlTmpl, data)
	if err != nil {
		return fmt.Errorf("render control: %w", err)
	}

	// Validate: load the generated YAML through the real control loader.
	if err := validateControlYAML([]byte(controlYAML)); err != nil {
		return fmt.Errorf("generated control is invalid: %w", err)
	}

	// Write control to both fixtures (each fixture is self-contained).
	for _, dir := range []string{failDir, passDir} {
		ctlDir := filepath.Join(dir, "controls")
		if err := os.MkdirAll(ctlDir, 0o755); err != nil {
			return fmt.Errorf("create dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(ctlDir, cfg.ID+".yaml"), []byte(controlYAML), 0o644); err != nil {
			return fmt.Errorf("write control: %w", err)
		}
	}
	fmt.Fprintf(cfg.Stdout, "  control:  %s\n", filepath.Join(failDir, "controls", cfg.ID+".yaml"))

	// ── Fail fixture (unsafe at both T1 and T2) ──────────────
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	if err := writeFixture(failDir, cfg, t1, t2, cfg.Value, cfg.Value, "3", "1"); err != nil {
		return err
	}
	fmt.Fprintf(cfg.Stdout, "  fail:     %s (exit=3, findings=1)\n", failDir)

	// ── Pass fixture (safe at both T1 and T2) ────────────────
	if err := writeFixture(passDir, cfg, t1, t2, cfg.SafeValue, cfg.SafeValue, "0", "0"); err != nil {
		return err
	}
	fmt.Fprintf(cfg.Stdout, "  pass:     %s (exit=0, findings=0)\n", passDir)

	fmt.Fprintln(cfg.Stdout)
	fmt.Fprintln(cfg.Stdout, "Next steps:")
	fmt.Fprintf(cfg.Stdout, "  1. Review: %s\n", filepath.Join(failDir, "controls", cfg.ID+".yaml"))
	fmt.Fprintln(cfg.Stdout, "  2. Generate golden files: make regenerate-goldens")
	fmt.Fprintln(cfg.Stdout, "  3. Run E2E tests: make e2e")

	return nil
}

func writeFixture(dir string, cfg config, t1, t2 time.Time, valueT1, valueT2, exitCode, findingsCount string) error {
	obsDir := filepath.Join(dir, "observations")
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	obs1 := buildObservation(t1, cfg.AssetType, cfg.Kind, cfg.KindField, cfg.Field, valueT1)
	obs2 := buildObservation(t2, cfg.AssetType, cfg.Kind, cfg.KindField, cfg.Field, valueT2)

	if err := writeJSON(filepath.Join(obsDir, "2026-01-01T000000Z.json"), obs1); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(obsDir, "2026-01-11T000000Z.json"), obs2); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "args.txt"), []byte(""), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "expected.exit"), []byte(exitCode+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "expected.findings.count"), []byte(findingsCount+"\n"), 0o644); err != nil {
		return err
	}
	return nil
}

// ── Template ─────────────────────────────────────────────────

type templateData struct {
	ID          string
	Name        string
	Domain      string
	Severity    string
	ScopeTags   []string
	Kind        string
	KindField   string
	Field       string
	Op          string
	Value       string
	Description string
	Remediation string
	Compliance  map[string]string
}

var controlTmpl = `dsl_version: ctrl.v1
id: {{ .ID }}
name: {{ quote .Name }}
description: >
  {{ .Description }}
domain: {{ .Domain }}
severity: {{ .Severity }}
{{- if .Compliance }}
compliance:
{{- range $k, $v := .Compliance }}
  {{ $k }}: {{ quote $v }}
{{- end }}
{{- end }}
scope_tags:
{{- range .ScopeTags }}
  - {{ quote . }}
{{- end }}
type: unsafe_state
params: {}
remediation:
  description: >
    {{ .Description }}
  action: >
    {{ .Remediation }}
unsafe_predicate:
  all:
{{- if .Kind }}
    - field: {{ quote .KindField }}
      op: eq
      value: {{ quote .Kind }}
{{- end }}
    - field: {{ quote .Field }}
      op: {{ .Op }}
      value: {{ .Value }}
`

var tmplFuncs = template.FuncMap{
	"quote": yamlutil.Quote,
}

func renderTemplate(tmpl string, data templateData) (string, error) {
	t, err := template.New("control").Funcs(tmplFuncs).Parse(tmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ── Validation ───────────────────────────────────────────────

func validateControlYAML(yamlBytes []byte) error {
	ctl, err := ctlyaml.UnmarshalControlDefinition(yamlBytes)
	if err != nil {
		return fmt.Errorf("YAML parse: %w", err)
	}
	if err := ctl.Prepare(); err != nil {
		return fmt.Errorf("predicate compile: %w", err)
	}
	return nil
}

// ── Observation generation ───────────────────────────────────

func buildObservation(capturedAt time.Time, assetType, kind, kindField, field, value string) map[string]any {
	props := buildNestedProps(field, parseValue(value))

	// Merge kind properties if specified.
	if kind != "" && kindField != "" {
		kindProps := buildNestedProps(kindField, kind)
		props = mergeMaps(props, kindProps)
	}

	return map[string]any{
		"schema_version": "obs.v0.1",
		"captured_at":    capturedAt.Format(time.RFC3339),
		"assets": []any{
			map[string]any{
				"id":         assetIDFromType(assetType),
				"type":       assetType,
				"vendor":     "aws",
				"properties": props,
			},
		},
	}
}

func buildNestedProps(fieldPath string, value any) map[string]any {
	path := strings.TrimPrefix(fieldPath, "properties.")
	parts := strings.Split(path, ".")

	result := value
	for i := len(parts) - 1; i >= 0; i-- {
		result = map[string]any{parts[i]: result}
	}
	if m, ok := result.(map[string]any); ok {
		return m
	}
	return map[string]any{parts[0]: result}
}

// mergeMaps recursively merges src into dst.
func mergeMaps(dst, src map[string]any) map[string]any {
	for k, sv := range src {
		dv, exists := dst[k]
		if !exists {
			dst[k] = sv
			continue
		}
		dMap, dOK := dv.(map[string]any)
		sMap, sOK := sv.(map[string]any)
		if dOK && sOK {
			dst[k] = mergeMaps(dMap, sMap)
		} else {
			dst[k] = sv
		}
	}
	return dst
}

// ── Helpers ──────────────────────────────────────────────────

func assetIDFromType(assetType string) string {
	_, rest, ok := strings.Cut(assetType, "_")
	if ok && rest != "" {
		return "test-" + strings.ReplaceAll(rest, "_", "-")
	}
	return "test-asset"
}

func defaultFixtureName(controlID, suffix string) string {
	parts := strings.Split(strings.ToLower(controlID), ".")
	meaningful := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "ctl" {
			continue
		}
		if len(p) > 0 && p[0] >= '0' && p[0] <= '9' {
			continue
		}
		meaningful = append(meaningful, p)
	}
	return "e2e-forge-" + strings.Join(meaningful, "-") + "-" + suffix
}

func defaultKindField(domain string) string {
	switch domain {
	case "identity":
		return "properties.identity.kind"
	default:
		return "properties.storage.kind"
	}
}

// sanitizeScalar collapses newlines and carriage returns to spaces.
// Used for values placed inside YAML folded block scalars (>) where
// an unindented newline would break out of the scalar and inject
// arbitrary YAML structure.
func sanitizeScalar(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

func shortField(field string) string {
	return field[strings.LastIndexByte(field, '.')+1:]
}

func invertValue(v string) string {
	switch v {
	case "true":
		return "false"
	case "false":
		return "true"
	default:
		return v
	}
}

func typedValue(v string) string {
	switch v {
	case "true", "false":
		return v
	default:
		for _, c := range v {
			if c < '0' || c > '9' {
				return yamlutil.Quote(v)
			}
		}
		return v
	}
}

func parseValue(v string) any {
	switch v {
	case "true":
		return true
	case "false":
		return false
	default:
		return v
	}
}

func parseCompliance(s string) map[string]string {
	if s == "" {
		return nil
	}
	result := make(map[string]string)
	for pair := range strings.SplitSeq(s, ",") {
		if k, v, ok := strings.Cut(pair, "="); ok {
			result[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return result
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
