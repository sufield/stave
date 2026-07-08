package validator

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/report"
)

func TestValidateAttestation_PassesSchemaValidation(t *testing.T) {
	v := report.NewAttestation(report.AttestationRequest{
		Run: report.AttestationRunInfo{
			ToolVersion:     "0.1.0",
			Offline:         true,
			EvalTime:        time.Now(),
			SLAThreshold:    24 * time.Hour,
			BeforeSnapshots: 1,
			AfterSnapshots:  1,
		},
		Summary: report.AttestationSummary{
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
