package engine

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/crypto"
)

func makeTestAssessor(controls []policy.ControlDefinition) *Assessor {
	return &Assessor{
		controls: controls,
		hasher:   crypto.NewHasher(),
	}
}

func TestFingerprintPolicy_Deterministic(t *testing.T) {
	controls := []policy.ControlDefinition{
		{ID: "CTL.S3.PUBLIC.001", Severity: policy.SeverityCritical, Type: policy.TypeUnsafeState},
		{ID: "CTL.S3.ENCRYPT.001", Severity: policy.SeverityHigh, Type: policy.TypeUnsafeState},
	}

	a := makeTestAssessor(controls)
	results := make([]string, 10)
	for i := range results {
		results[i] = string(a.FingerprintPolicy())
	}

	for i := 1; i < len(results); i++ {
		if results[i] != results[0] {
			t.Errorf("non-deterministic: run 0 = %q, run %d = %q", results[0], i, results[i])
		}
	}
}

func TestFingerprintPolicy_SeverityChangeDetected(t *testing.T) {
	original := []policy.ControlDefinition{
		{ID: "CTL.S3.PUBLIC.001", Severity: policy.SeverityCritical, Type: policy.TypeUnsafeState},
	}
	weakened := []policy.ControlDefinition{
		{ID: "CTL.S3.PUBLIC.001", Severity: policy.SeverityLow, Type: policy.TypeUnsafeState},
	}

	fp1 := makeTestAssessor(original).FingerprintPolicy()
	fp2 := makeTestAssessor(weakened).FingerprintPolicy()

	if fp1 == fp2 {
		t.Errorf("AUDIT BYPASS: severity change not detected — fingerprint %q unchanged", fp1)
	}
}

func TestFingerprintPolicy_TypeChangeDetected(t *testing.T) {
	a := []policy.ControlDefinition{
		{ID: "CTL.TEST.001", Severity: policy.SeverityHigh, Type: policy.TypeUnsafeState},
	}
	b := []policy.ControlDefinition{
		{ID: "CTL.TEST.001", Severity: policy.SeverityHigh, Type: policy.TypeUnsafeDuration},
	}

	fp1 := makeTestAssessor(a).FingerprintPolicy()
	fp2 := makeTestAssessor(b).FingerprintPolicy()

	if fp1 == fp2 {
		t.Error("control type change not detected in fingerprint")
	}
}

func TestFingerprintPolicy_IDChangeDetected(t *testing.T) {
	a := []policy.ControlDefinition{
		{ID: kernel.ControlID("CTL.S3.PUBLIC.001"), Severity: policy.SeverityCritical, Type: policy.TypeUnsafeState},
	}
	b := []policy.ControlDefinition{
		{ID: kernel.ControlID("CTL.S3.PUBLIC.002"), Severity: policy.SeverityCritical, Type: policy.TypeUnsafeState},
	}

	fp1 := makeTestAssessor(a).FingerprintPolicy()
	fp2 := makeTestAssessor(b).FingerprintPolicy()

	if fp1 == fp2 {
		t.Error("control ID change not detected in fingerprint")
	}
}
