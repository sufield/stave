package toolmap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestAnalyze_MinimalFixture(t *testing.T) {
	chainsDir := t.TempDir()
	controlsDir := t.TempDir()

	// Chain with postcondition matching a tool prerequisite.
	writeFile(t, chainsDir, "test_chain.yaml", `
id: test_credential_theft
description: test chain
controls:
  - CTL.IAM.TEST.001
escalation_threshold: 1
compound_severity: high
postconditions:
  - iam_credential_theft
`)

	// Control with field path matching a tool prerequisite.
	writeFile(t, controlsDir, "CTL.IAM.TEST.001.yaml", `
dsl_version: ctrl.v1
id: CTL.IAM.TEST.001
name: Test Control
description: test
domain: exposure
severity: high
type: unsafe_state
classification: state_assertion
applicable_asset_types:
  - aws_iam_role
unsafe_predicate:
  all:
    - field: properties.identity.policies.has_admin_access
      op: eq
      value: true
`)

	r := NewRegistry()
	result, err := Analyze(r, chainsDir, testControlLoader, controlsDir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	if len(result.Covered) == 0 && len(result.Gaps) == 0 {
		t.Fatal("expected some coverage results")
	}

	// The pacu tool has an iam_credential_theft prerequisite with
	// field path properties.identity.policies.has_admin_access.
	// The chain provides the capability, the control checks the field.
	foundCovered := false
	for _, c := range result.Covered {
		if c.Tool == "pacu" && c.Capability == "iam_credential_theft" {
			foundCovered = true
			if len(c.ChainIDs) == 0 {
				t.Error("covered entry should have chain IDs")
			}
			if len(c.ControlIDs) == 0 {
				t.Error("covered entry should have control IDs")
			}
		}
	}
	if !foundCovered {
		t.Error("pacu iam_credential_theft should be covered by test fixtures")
	}

	// There should be gaps — not all tool prerequisites are
	// covered by the minimal fixtures.
	if len(result.Gaps) == 0 {
		t.Error("expected some gaps from the minimal fixture")
	}
}

func TestAnalyze_EmptyDirs(t *testing.T) {
	chainsDir := t.TempDir()
	controlsDir := t.TempDir()

	r := NewRegistry()
	result, err := Analyze(r, chainsDir, testControlLoader, controlsDir)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}

	// All prerequisites should be gaps (no chains or controls).
	if len(result.Covered) != 0 {
		t.Error("expected no covered entries with empty dirs")
	}
	if len(result.Gaps) == 0 {
		t.Error("expected gaps when no chains or controls exist")
	}
	for _, g := range result.Gaps {
		if g.HasChain || g.HasControl {
			t.Errorf("gap %s/%s should have no chain or control", g.Tool, g.Capability)
		}
	}
}

type testControlDTO struct {
	ID              kernel.ControlID `yaml:"id"`
	UnsafePredicate testPredicateDTO `yaml:"unsafe_predicate"`
}

type testPredicateDTO struct {
	Any []testRuleDTO `yaml:"any,omitempty"`
	All []testRuleDTO `yaml:"all,omitempty"`
}

type testRuleDTO struct {
	Field string             `yaml:"field,omitempty"`
	Op    predicate.Operator `yaml:"op,omitempty"`
	Value any                `yaml:"value,omitempty"`
	Any   []testRuleDTO      `yaml:"any,omitempty"`
	All   []testRuleDTO      `yaml:"all,omitempty"`
}

func testControlLoader(rootDir string) ([]policy.ControlDefinition, error) {
	var all []policy.ControlDefinition
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".yaml") {
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // test helper
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		var dto testControlDTO
		if yamlErr := yaml.Unmarshal(data, &dto); yamlErr != nil {
			return fmt.Errorf("parse %s: %w", path, yamlErr)
		}
		ctl := policy.ControlDefinition{
			ID:              dto.ID,
			UnsafePredicate: convertPredicate(dto.UnsafePredicate),
		}
		all = append(all, ctl)
		return nil
	})
	return all, err
}

func convertPredicate(p testPredicateDTO) policy.UnsafePredicate {
	return policy.UnsafePredicate{
		Any: convertRules(p.Any),
		All: convertRules(p.All),
	}
}

func convertRules(rules []testRuleDTO) []policy.PredicateRule {
	out := make([]policy.PredicateRule, len(rules))
	for i, r := range rules {
		out[i] = policy.PredicateRule{
			Field: predicate.NewFieldPath(r.Field),
			Op:    r.Op,
			Value: policy.NewOperand(r.Value),
			Any:   convertRules(r.Any),
			All:   convertRules(r.All),
		}
	}
	return out
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
