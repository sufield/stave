package report

import (
	"testing"
	"time"
)

func TestBugHunt_ValidateAttestation_PassesSchemaValidation(t *testing.T) {
	v := NewAttestation(AttestationRequest{
		Run: AttestationRunInfo{
			ToolVersion:     "0.1.0",
			Offline:         true,
			EvalTime:        time.Now(),
			SLAThreshold:    24 * time.Hour,
			BeforeSnapshots: 1,
			AfterSnapshots:  1,
		},
		Summary: AttestationSummary{
			PreviousViolations: 1,
			CurrentViolations:  0,
			Remediated:         1,
			Open:               0,
			Regressions:        0,
		},
	})

	if err := ValidateAttestation(v); err != nil {
		t.Fatalf("ValidateAttestation failed: %v", err)
	}
}
