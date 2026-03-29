package status

import (
	"bytes"
	"testing"

	appstatus "github.com/sufield/stave/internal/app/status"
	"github.com/sufield/stave/internal/cli/ui"
)

func TestRunnerReport_JSON(t *testing.T) {
	r := &Runner{}
	var buf bytes.Buffer
	cfg := config{
		Format: ui.OutputFormatJSON,
		Stdout: &buf,
	}
	result := appstatus.Result{
		State:       appstatus.ProjectState{Root: "/tmp/project"},
		NextCommand: "stave apply",
	}
	if err := r.report(cfg, result); err != nil {
		t.Fatalf("report error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected JSON output")
	}
}

func TestRunnerReport_Text(t *testing.T) {
	r := &Runner{}
	var buf bytes.Buffer
	cfg := config{
		Format: ui.OutputFormatText,
		Stdout: &buf,
	}
	result := appstatus.Result{
		State:       appstatus.ProjectState{Root: "/tmp/project"},
		NextCommand: "stave apply",
	}
	if err := r.report(cfg, result); err != nil {
		t.Fatalf("report error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected text output")
	}
}
