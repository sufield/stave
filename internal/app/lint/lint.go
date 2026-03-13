package lint

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Severity represents the severity of a lint diagnostic.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
)

// Diagnostic represents a single lint finding with file position.
type Diagnostic struct {
	Path     string   `json:"path"`
	Line     int      `json:"line"`
	Col      int      `json:"col"`
	RuleID   string   `json:"rule_id"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

// Linter performs quality checks on control YAML definitions.
type Linter struct {
	idPattern *regexp.Regexp
}

// NewLinter creates a Linter with the standard rule set.
func NewLinter() *Linter {
	return &Linter{
		idPattern: regexp.MustCompile(`^[A-Z]+\.[A-Z0-9_]+\.[0-9]{3}$`),
	}
}

// LintBytes performs quality checks on the provided YAML data.
func (l *Linter) LintBytes(path string, data []byte) []Diagnostic {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return []Diagnostic{{
			Path:     path,
			Line:     1,
			Col:      1,
			RuleID:   "CTL_YAML_PARSE",
			Message:  "invalid YAML: " + err.Error(),
			Severity: SeverityError,
		}}
	}

	root := &doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root = doc.Content[0]
	}

	var diags []Diagnostic
	diags = append(diags, l.checkVersion(path, root)...)
	diags = append(diags, l.checkID(path, root)...)
	diags = append(diags, l.checkMetadata(path, root)...)
	diags = append(diags, l.walkDeterminism(path, root)...)
	diags = append(diags, l.walkOrdering(path, root)...)

	return diags
}

// --- Rules ---

func (l *Linter) checkID(path string, root *yaml.Node) []Diagnostic {
	id, key := getString(root, "id")
	if id == "" {
		return []Diagnostic{newDiag(path, 1, 1, "CTL_ID_REQUIRED", "id is required", SeverityError)}
	}

	trimmedID := strings.TrimPrefix(strings.TrimSpace(id), "CTL.")
	if !l.idPattern.MatchString(trimmedID) {
		line, col := nodePos(key)
		return []Diagnostic{newDiag(path, line, col, "CTL_ID_NAMESPACE",
			"id must follow namespace pattern [A-Z]+.[A-Z0-9_]+.[0-9]{3} (CTL. prefix allowed)", SeverityError)}
	}
	return nil
}

func (l *Linter) checkMetadata(path string, root *yaml.Node) []Diagnostic {
	name, nameKey := getString(root, "name")
	description, descriptionKey := getString(root, "description")
	var remediationAction string
	var remediationActionKey *yaml.Node
	_, remediation := findNode(root, "remediation")
	if remediation != nil && remediation.Kind == yaml.MappingNode {
		remediationAction, remediationActionKey = getString(remediation, "action")
	}

	checks := []struct {
		value string
		key   *yaml.Node
		rule  string
		name  string
	}{
		{value: name, key: nameKey, rule: "CTL_META_NAME_REQUIRED", name: "name"},
		{value: description, key: descriptionKey, rule: "CTL_META_DESCRIPTION_REQUIRED", name: "description"},
		{value: remediationAction, key: remediationActionKey, rule: "CTL_META_REMEDIATION_REQUIRED", name: "remediation"},
	}

	var diags []Diagnostic
	for _, check := range checks {
		if check.value == "" {
			line, col := nodePos(check.key)
			diags = append(diags, newDiag(path, line, col, check.rule, check.name+" metadata is required", SeverityError))
		}
	}
	return diags
}

func (l *Linter) checkVersion(path string, root *yaml.Node) []Diagnostic {
	val, key := getString(root, "dsl_version")
	if val == "" {
		return []Diagnostic{newDiag(path, 1, 1, "CTL_SCHEMA_ASSUMED_V1",
			"dsl_version is missing; lint assumes "+string(kernel.SchemaControl), SeverityWarn)}
	}

	if val != string(kernel.SchemaControl) {
		line, col := nodePos(key)
		return []Diagnostic{newDiag(path, line, col, "CTL_SCHEMA_UNSUPPORTED",
			"dsl_version must be one of: "+string(kernel.SchemaControl), SeverityError)}
	}
	return nil
}

var forbiddenFields = map[string]bool{
	"now": true, "timestamp": true, "generated_at": true, "runtime": true,
}

func (l *Linter) walkDeterminism(path string, n *yaml.Node) []Diagnostic {
	var diags []Diagnostic
	walk(n, func(k, v *yaml.Node) {
		key := strings.ToLower(strings.TrimSpace(k.Value))
		if forbiddenFields[key] {
			diags = append(diags, newDiag(path, k.Line, k.Column, "CTL_NONDETERMINISTIC_FIELD",
				fmt.Sprintf("field %q is not allowed in control contracts", k.Value), SeverityError))
		}
	})
	return diags
}

func (l *Linter) walkOrdering(path string, n *yaml.Node) []Diagnostic {
	var diags []Diagnostic
	walk(n, func(k, v *yaml.Node) {
		if v.Kind == yaml.SequenceNode && !isSortedSequence(v) {
			diags = append(diags, newDiag(path, k.Line, k.Column, "CTL_ORDERING_HINT",
				fmt.Sprintf("array %q should include deterministic sort keys (id/name/key/type)", k.Value), SeverityWarn))
		}
	})
	return diags
}

// --- YAML Helpers ---

func findNode(node *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k, v := node.Content[i], node.Content[i+1]
		if k.Value == key {
			return k, v
		}
	}
	return nil, nil
}

func getString(node *yaml.Node, keys ...string) (string, *yaml.Node) {
	for _, key := range keys {
		k, v := findNode(node, key)
		if k != nil && v != nil && v.Kind == yaml.ScalarNode {
			return strings.TrimSpace(v.Value), k
		}
	}
	return "", nil
}

func walk(n *yaml.Node, fn func(k, v *yaml.Node)) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			fn(k, v)
			walk(v, fn)
		}
		return
	}
	for _, c := range n.Content {
		walk(c, fn)
	}
}

func isSortedSequence(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		return true
	}
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			return true
		}
		hasSortableKey := false
		for i := 0; i+1 < len(item.Content); i += 2 {
			switch strings.ToLower(strings.TrimSpace(item.Content[i].Value)) {
			case "id", "name", "key", "type":
				hasSortableKey = true
			}
		}
		if !hasSortableKey {
			return false
		}
	}
	return true
}

func newDiag(path string, line, col int, id, msg string, sev Severity) Diagnostic {
	if line <= 0 {
		line = 1
	}
	if col <= 0 {
		col = 1
	}
	return Diagnostic{Path: path, Line: line, Col: col, RuleID: id, Message: msg, Severity: sev}
}

func nodePos(n *yaml.Node) (int, int) {
	if n == nil {
		return 1, 1
	}
	return n.Line, n.Column
}
