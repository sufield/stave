package contextcmd

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

func TestContextCreateUseShowDeleteFlow(t *testing.T) {
	t.Setenv("STAVE_CONTEXTS_FILE", filepath.Join(t.TempDir(), "contexts.yaml"))

	project := t.TempDir()

	if err := runContextCreate(CreateInput{
		Stdout: io.Discard, Name: "prod", Dir: project, ConfigFile: "stave.yaml",
		ControlsDir: "controls", ObservationsDir: "observations",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := runContextUse(UseInput{Stdout: io.Discard, Name: "prod"}); err != nil {
		t.Fatalf("use: %v", err)
	}

	var showBuf bytes.Buffer
	if err := runContextShow(ShowInput{Stdout: &showBuf, Format: appcontracts.FormatJSON}); err != nil {
		t.Fatalf("show: %v", err)
	}
	out := showBuf.String()
	if !strings.Contains(out, "\"name\": \"prod\"") {
		t.Fatalf("show output missing context name: %s", out)
	}

	if err := runContextDelete(DeleteInput{Stdout: io.Discard, Name: "prod"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestContextListSorted(t *testing.T) {
	t.Setenv("STAVE_CONTEXTS_FILE", filepath.Join(t.TempDir(), "contexts.yaml"))

	project := t.TempDir()
	for _, name := range []string{"zeta", "alpha"} {
		if err := runContextCreate(CreateInput{
			Stdout: io.Discard, Name: name, Dir: project, ConfigFile: "stave.yaml",
			ControlsDir: "controls", ObservationsDir: "observations",
		}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	var buf bytes.Buffer
	if err := runContextList(ListInput{Stdout: &buf, Format: appcontracts.FormatText}); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := buf.String()
	if strings.Index(out, "alpha") > strings.Index(out, "zeta") {
		t.Fatalf("contexts not sorted: %s", out)
	}
}
