package schemaval

import (
	"encoding/json"
	"testing"

	"github.com/sufield/stave/internal/core/outcome"
)

func TestReadinessAssessment_JSONSerde_PreservesFindings(t *testing.T) {
	t.Parallel()

	ra := NewReadinessAssessment("controls/", "obs/")
	ra.RecordFinding(ValidationFinding{
		Name:    "check_encryption",
		Status:  outcome.Fail,
		Message: "S3 bucket missing encryption",
	})

	if len(ra.Findings()) == 0 {
		t.Fatal("expected 1 finding before serde")
	}

	data, err := json.Marshal(ra)
	if err != nil {
		t.Fatalf("failed to marshal ReadinessAssessment: %v", err)
	}

	var unmarshaled ReadinessAssessment
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal ReadinessAssessment: %v", err)
	}

	if len(unmarshaled.Findings()) != 1 {
		t.Fatalf("CRITICAL BUG: JSON serde lost findings; got %d findings after unmarshal, want 1", len(unmarshaled.Findings()))
	}
}
