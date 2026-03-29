package json

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func TestWriteDiagnosis(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{},
	}
	var buf bytes.Buffer
	err := WriteDiagnosis(&buf, report)
	if err != nil {
		t.Fatalf("WriteDiagnosis() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "diagnose") {
		t.Fatalf("expected 'diagnose' in output: %s", out)
	}
}

func TestWriteVerification(t *testing.T) {
	result := safetyenvelope.NewVerification(safetyenvelope.VerificationRequest{})
	var buf bytes.Buffer
	err := WriteVerification(&buf, result)
	if err != nil {
		t.Fatalf("WriteVerification() error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "verification") {
		t.Fatalf("expected 'verification' in output: %s", out)
	}
}
