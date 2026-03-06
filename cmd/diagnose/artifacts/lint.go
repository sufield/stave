package artifacts

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var lintIDPattern = regexp.MustCompile(`^[A-Z]+\.[A-Z0-9_]+\.[0-9]{3}$`)

type lintSeverity string

const (
	lintSeverityError lintSeverity = "error"
	lintSeverityWarn  lintSeverity = "warn"
)

type lintDiagnostic struct {
	Path     string
	Line     int
	Col      int
	RuleID   string
	Message  string
	Severity lintSeverity
}

var LintCmd = &cobra.Command{
	Use:   "lint <path>",
	Short: "Lint control files for design quality",
	Long: `Lint checks control design quality rules independent of schema validity.
It is deterministic, offline, and file-based.

Rules:
  - ID namespace format
  - Required metadata (name/description/remediation)
  - Determinism key constraints
  - Stable ordering hints for list-like sections` + metadata.OfflineHelpSuffix,
	Args:          cobra.ExactArgs(1),
	RunE:          runLint,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func lintPathNode(node *yaml.Node, key string) (*yaml.Node, *yaml.Node) {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		v := node.Content[i+1]
		if k.Value == key {
			return k, v
		}
	}
	return nil, nil
}

func lintGetString(node *yaml.Node, keys ...string) (string, *yaml.Node) {
	for _, key := range keys {
		k, v := lintPathNode(node, key)
		if k != nil && v != nil && v.Kind == yaml.ScalarNode {
			return strings.TrimSpace(v.Value), k
		}
	}
	return "", nil
}

func lintAdd(diags *[]lintDiagnostic, d lintDiagnostic) {
	if d.Line <= 0 {
		d.Line = 1
	}
	if d.Col <= 0 {
		d.Col = 1
	}
	*diags = append(*diags, d)
}

func lintIDNamespace(id string) bool {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "CTL.")
	return lintIDPattern.MatchString(id)
}

func lintCheckID(path string, root *yaml.Node, diags *[]lintDiagnostic) {
	id, key := lintGetString(root, "id")
	if id == "" {
		lintAdd(diags, lintDiagnostic{
			Path:     path,
			Line:     1,
			Col:      1,
			RuleID:   "CTL_ID_REQUIRED",
			Message:  "id is required",
			Severity: lintSeverityError,
		})
		return
	}
	if !lintIDNamespace(id) {
		line, col := 1, 1
		if key != nil {
			line, col = key.Line, key.Column
		}
		lintAdd(diags, lintDiagnostic{
			Path:     path,
			Line:     line,
			Col:      col,
			RuleID:   "CTL_ID_NAMESPACE",
			Message:  "id must follow namespace pattern [A-Z]+.[A-Z0-9_]+.[0-9]{3} (CTL. prefix allowed)",
			Severity: lintSeverityError,
		})
	}
}

func lintCheckMetadata(path string, root *yaml.Node, diags *[]lintDiagnostic) {
	name, nameKey := lintGetString(root, "name")
	description, descriptionKey := lintGetString(root, "description")
	var remediationAction string
	var remediationActionKey *yaml.Node
	_, remediation := lintPathNode(root, "remediation")
	if remediation != nil && remediation.Kind == yaml.MappingNode {
		remediationAction, remediationActionKey = lintGetString(remediation, "action")
	}

	missing := []struct {
		value string
		key   *yaml.Node
		rule  string
		name  string
	}{
		{value: name, key: nameKey, rule: "CTL_META_NAME_REQUIRED", name: "name"},
		{value: description, key: descriptionKey, rule: "CTL_META_DESCRIPTION_REQUIRED", name: "description"},
		{value: remediationAction, key: remediationActionKey, rule: "CTL_META_REMEDIATION_REQUIRED", name: "remediation"},
	}

	for _, item := range missing {
		if item.value == "" {
			line, col := 1, 1
			if item.key != nil {
				line, col = item.key.Line, item.key.Column
			}
			lintAdd(diags, lintDiagnostic{
				Path:     path,
				Line:     line,
				Col:      col,
				RuleID:   item.rule,
				Message:  item.name + " metadata is required",
				Severity: lintSeverityError,
			})
		}
	}
}

func lintCheckVersion(path string, root *yaml.Node, diags *[]lintDiagnostic) {
	dslValue, dslKey := lintGetString(root, "dsl_version")
	if dslValue == "" {
		lintAdd(diags, lintDiagnostic{
			Path:     path,
			Line:     1,
			Col:      1,
			RuleID:   "CTL_SCHEMA_ASSUMED_V1",
			Message:  "dsl_version is missing; lint assumes " + string(kernel.SchemaControl),
			Severity: lintSeverityWarn,
		})
		return
	}
	acceptedVersions := []string{string(kernel.SchemaControl)}
	if !slices.Contains(acceptedVersions, dslValue) {
		line, col := 1, 1
		if dslKey != nil {
			line, col = dslKey.Line, dslKey.Column
		}
		lintAdd(diags, lintDiagnostic{
			Path:     path,
			Line:     line,
			Col:      col,
			RuleID:   "CTL_SCHEMA_UNSUPPORTED",
			Message:  "dsl_version must be one of: " + strings.Join(acceptedVersions, ", "),
			Severity: lintSeverityError,
		})
	}
}

func lintWalkDeterminism(path string, n *yaml.Node, diags *[]lintDiagnostic) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			key := strings.ToLower(strings.TrimSpace(k.Value))
			if key == "now" || key == "timestamp" || key == "generated_at" || key == "runtime" {
				lintAdd(diags, lintDiagnostic{
					Path:     path,
					Line:     k.Line,
					Col:      k.Column,
					RuleID:   "CTL_NONDETERMINISTIC_FIELD",
					Message:  fmt.Sprintf("field %q is not allowed in control contracts", k.Value),
					Severity: lintSeverityError,
				})
			}
			lintWalkDeterminism(path, v, diags)
		}
		return
	}
	for _, c := range n.Content {
		lintWalkDeterminism(path, c, diags)
	}
}

func lintSequenceHasSortKey(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.SequenceNode || len(n.Content) == 0 {
		return true
	}
	for _, item := range n.Content {
		if item.Kind != yaml.MappingNode {
			return true
		}
		hasSortableKey := false
		for i := 0; i+1 < len(item.Content); i += 2 {
			k := item.Content[i]
			switch strings.ToLower(strings.TrimSpace(k.Value)) {
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

func lintWalkOrdering(path string, n *yaml.Node, diags *[]lintDiagnostic) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			v := n.Content[i+1]
			if v.Kind == yaml.SequenceNode && !lintSequenceHasSortKey(v) {
				lintAdd(diags, lintDiagnostic{
					Path:     path,
					Line:     k.Line,
					Col:      k.Column,
					RuleID:   "CTL_ORDERING_HINT",
					Message:  fmt.Sprintf("array %q should include deterministic sort keys (id/name/key/type)", k.Value),
					Severity: lintSeverityWarn,
				})
			}
			lintWalkOrdering(path, v, diags)
		}
		return
	}
	for _, c := range n.Content {
		lintWalkOrdering(path, c, diags)
	}
}

func lintOneFile(path string) ([]lintDiagnostic, error) {
	raw, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(raw, &doc); err != nil {
		return []lintDiagnostic{{
			Path:     path,
			Line:     1,
			Col:      1,
			RuleID:   "CTL_YAML_PARSE",
			Message:  "invalid YAML: " + err.Error(),
			Severity: lintSeverityError,
		}}, nil
	}
	root := &doc
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root = doc.Content[0]
	}
	var diags []lintDiagnostic
	lintCheckVersion(path, root, &diags)
	lintCheckID(path, root, &diags)
	lintCheckMetadata(path, root, &diags)
	lintWalkDeterminism(path, root, &diags)
	lintWalkOrdering(path, root, &diags)
	return diags, nil
}

func lintCollectFiles(rootPath string) ([]string, error) {
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(rootPath))
		if ext == ".yaml" || ext == ".yml" {
			return []string{rootPath}, nil
		}
		return nil, fmt.Errorf("unsupported file type %q", rootPath)
	}

	var files []string
	err = filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(files)
	return files, nil
}

func sortLintDiagnostics(diags []lintDiagnostic) {
	slices.SortFunc(diags, compareLintDiagnostic)
}

func compareLintDiagnostic(a, b lintDiagnostic) int {
	if cmp := strings.Compare(a.Path, b.Path); cmp != 0 {
		return cmp
	}
	if cmp := compareLintInt(a.Line, b.Line); cmp != 0 {
		return cmp
	}
	if cmp := compareLintInt(a.Col, b.Col); cmp != 0 {
		return cmp
	}
	if cmp := strings.Compare(a.RuleID, b.RuleID); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.Message, b.Message)
}

func compareLintInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func runLint(cmd *cobra.Command, args []string) error {
	target := fsutil.CleanUserPath(args[0])
	files, err := lintCollectFiles(target)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no control YAML files found in %s", target)
	}

	var all []lintDiagnostic
	for _, file := range files {
		diags, lintErr := lintOneFile(file)
		if lintErr != nil {
			return fmt.Errorf("lint %s: %w", file, lintErr)
		}
		all = append(all, diags...)
	}
	sortLintDiagnostics(all)

	errorCount := 0
	for _, d := range all {
		if d.Severity == lintSeverityError {
			errorCount++
		}
		if _, err = fmt.Fprintf(cmd.OutOrStdout(), "%s:%d:%d  %s  %s\n", d.Path, d.Line, d.Col, d.RuleID, d.Message); err != nil {
			return err
		}
	}

	if errorCount > 0 {
		return ui.ErrValidationFailed
	}
	return nil
}
