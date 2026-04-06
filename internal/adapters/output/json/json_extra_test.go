package json

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/core/report"
)

func TestWriteDiagnosis(t *testing.T) {
	diagReport := &diagnosis.Report{
		Issues: []diagnosis.Insight{},
	}
	var buf bytes.Buffer
	err := WriteDiagnosis(&buf, diagReport)
	if err != nil {
		t.Fatalf("WriteDiagnosis() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "diagnose") {
		t.Fatalf("expected 'diagnose' in output: %s", out)
	}
}

func TestWriteVerification(t *testing.T) {
	result := report.NewAttestation(report.AttestationRequest{})
	var buf bytes.Buffer
	err := WriteVerification(&buf, result)
	if err != nil {
		t.Fatalf("WriteVerification() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "ATTESTATION") {
		t.Fatalf("expected 'ATTESTATION' in output: %s", out)
	}
}
