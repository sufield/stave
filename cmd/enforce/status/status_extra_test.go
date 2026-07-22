package status

import (
	"bytes"
	"testing"

	"github.com/sufield/stave/cmd/cmdutil"
	appstatus "github.com/sufield/stave/pkg/stave/status"
)

func TestRunnerReport_JSON(t *testing.T) {
	r := &Runner{}
	var buf bytes.Buffer
	cfg := config{
		Format: cmdutil.FormatJSON,
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
		Format: cmdutil.FormatText,
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
