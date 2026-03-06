package text

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/kernel"
)

func plainLabel(_, message string) string { return message }

func TestWriteDiagnosisReport_NoDiagnoses(t *testing.T) {
	report := &diagnosis.Report{}
	report.Summary.TotalSnapshots = 2
	report.Summary.TotalResources = 1
	report.Summary.TotalControls = 1
	report.Summary.TimeSpan = kernel.Duration(time.Hour)
	report.Summary.MaxUnsafeThreshold = kernel.Duration(30 * time.Minute)
	report.Summary.ViolationsFound = 0
	report.Summary.AttackSurface = 0

	var buf bytes.Buffer
	if err := WriteDiagnosisReport(&buf, report, plainLabel); err != nil {
		t.Fatalf("WriteDiagnosisReport: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "No diagnostic issues detected.") {
		t.Fatalf("unexpected output: %s", out)
	}
	if !strings.Contains(out, "Next step: continue with `stave apply` on new snapshots.") {
		t.Fatalf("missing next-step hint: %s", out)
	}
}

func TestWriteDiagnosisReport_WithDiagnoses(t *testing.T) {
	report := &diagnosis.Report{}
	report.Summary.TotalSnapshots = 1
	report.Entries = []diagnosis.Entry{
		{Case: diagnosis.EmptyFindings, Signal: "info", Evidence: "none", Action: "ok"},
	}

	var buf bytes.Buffer
	if err := WriteDiagnosisReport(&buf, report, plainLabel); err != nil {
		t.Fatalf("WriteDiagnosisReport: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Diagnostics (1):") {
		t.Fatalf("missing diagnostics header: %s", out)
	}
	if !strings.Contains(out, string(diagnosis.EmptyFindings)) {
		t.Fatalf("missing diagnostic case: %s", out)
	}
	if !strings.Contains(out, "Next step: apply the suggested action/command") {
		t.Fatalf("missing next-step hint: %s", out)
	}
}
