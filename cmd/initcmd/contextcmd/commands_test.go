package contextcmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestContextCreateUseShowDeleteFlow(t *testing.T) {
	t.Setenv("STAVE_CONTEXTS_FILE", filepath.Join(t.TempDir(), "contexts.yaml"))

	project := t.TempDir()

	createCmd := &cobra.Command{}
	if err := runContextCreate(createCmd, []string{"prod"}, contextCreateInput{Dir: project, ConfigFile: "stave.yaml", ControlsDir: "controls", ObservationsDir: "observations"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	useCmd := &cobra.Command{}
	if err := runContextUse(useCmd, []string{"prod"}); err != nil {
		t.Fatalf("use: %v", err)
	}

	showCmd := &cobra.Command{}
	var showBuf bytes.Buffer
	showCmd.SetOut(&showBuf)
	if err := runContextShow(showCmd, "json"); err != nil {
		t.Fatalf("show: %v", err)
	}
	out := showBuf.String()
	if !strings.Contains(out, "\"name\": \"prod\"") {
		t.Fatalf("show output missing context name: %s", out)
	}

	delCmd := &cobra.Command{}
	if err := runContextDelete(delCmd, []string{"prod"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestContextListSorted(t *testing.T) {
	t.Setenv("STAVE_CONTEXTS_FILE", filepath.Join(t.TempDir(), "contexts.yaml"))

	project := t.TempDir()
	if err := runContextCreate(&cobra.Command{}, []string{"zeta"}, contextCreateInput{Dir: project, ConfigFile: "stave.yaml", ControlsDir: "controls", ObservationsDir: "observations"}); err != nil {
		t.Fatalf("create zeta: %v", err)
	}
	if err := runContextCreate(&cobra.Command{}, []string{"alpha"}, contextCreateInput{Dir: project, ConfigFile: "stave.yaml", ControlsDir: "controls", ObservationsDir: "observations"}); err != nil {
		t.Fatalf("create alpha: %v", err)
	}
	listCmd := &cobra.Command{}
	var buf bytes.Buffer
	listCmd.SetOut(&buf)
	if err := runContextList(listCmd, "text"); err != nil {
		t.Fatalf("list: %v", err)
	}
	out := buf.String()
	if strings.Index(out, "alpha") > strings.Index(out, "zeta") {
		t.Fatalf("contexts not sorted: %s", out)
	}
}
