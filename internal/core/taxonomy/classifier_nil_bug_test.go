package taxonomy

import (
	"testing"
)

func TestClassifier_NilReceiver(t *testing.T) {
	var c *Classifier
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Classify() panicked on nil receiver: %v", r)
		}
	}()

	cats := c.Classify("S3 bucket public")
	if len(cats) != 0 {
		t.Errorf("expected empty categories slice for nil classifier, got %v", cats)
	}

	catsFields := c.ClassifyFields("CTL.1", "name", "desc", []string{"properties.storage"})
	if len(catsFields) != 0 {
		t.Errorf("expected empty categories slice for nil classifier, got %v", catsFields)
	}
}
