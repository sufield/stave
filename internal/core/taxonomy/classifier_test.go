package taxonomy

import (
	"slices"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestClassifier_LeastPrivilege(t *testing.T) {
	c := NewClassifier()
	cats := c.Classify("CTL.IAM.POLICY.WILDCARD.001 IAM Policy Must Not Use Wildcard Actions")
	if !slices.Contains(cats, LeastPrivilege) {
		t.Errorf("expected least-privilege, got %v", cats)
	}
}

func TestClassifier_FormalSemantics(t *testing.T) {
	c := NewClassifier()
	cats := c.Classify("CTL.IAM.SEMANTICS.FORALLVALUES.001 ForAllValues vacuous satisfaction")
	if !slices.Contains(cats, FormalSemantics) {
		t.Errorf("expected formal-semantics, got %v", cats)
	}
}

func TestClassifier_Deprecation(t *testing.T) {
	c := NewClassifier()
	cats := c.Classify("CTL.LAMBDA.RUNTIME.EOL.001 Lambda Runtime End of Life")
	if !slices.Contains(cats, Deprecation) {
		t.Errorf("expected deprecation, got %v", cats)
	}
}

func TestClassifier_NoMatch(t *testing.T) {
	c := NewClassifier()
	cats := c.Classify("completely unrelated text with no keywords")
	if len(cats) != 0 {
		t.Errorf("expected empty, got %v", cats)
	}
}

func TestClassifier_MultipleMatches(t *testing.T) {
	c := NewClassifier()
	cats := c.Classify("CTL.EC2.SNAPSHOT.BLOCKPUBLIC.001 EBS Snapshot Block Public Access VPC endpoint KMS encrypt")
	if len(cats) < 2 {
		t.Errorf("expected multiple categories, got %v", cats)
	}
}

func TestClassifier_NoDuplicates(t *testing.T) {
	c := NewClassifier()
	cats := c.Classify("wildcard overperm admin_access broad wildcard")
	seen := make(map[kernel.CategoryID]bool)
	for _, cat := range cats {
		if seen[cat] {
			t.Errorf("duplicate category: %s", cat)
		}
		seen[cat] = true
	}
}

func TestClassifyFields(t *testing.T) {
	c := NewClassifier()
	cats := c.ClassifyFields(
		"CTL.IAM.POLICY.WILDCARD.001",
		"IAM Policy Must Not Use Wildcard Actions",
		"Detects overly permissive IAM policies",
		[]string{"properties.policy.actions"},
	)
	if !slices.Contains(cats, LeastPrivilege) {
		t.Errorf("expected least-privilege, got %v", cats)
	}
}
