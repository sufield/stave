package status

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
	appstatus "github.com/sufield/stave/internal/app/status"
)

func TestRecommendNextCreateControlWhenMissing(t *testing.T) {
	root := "/tmp/project"

	next := State{
		ProjectState: appstatus.ProjectState{
			Root:         root,
			Controls:     appstatus.Summary{},
			RawSnapshots: appstatus.Summary{},
			Observations: appstatus.Summary{Count: 1, HasLatest: true, Latest: time.Now().Add(-2 * time.Hour)},
		},
	}.RecommendNext()
	if !strings.Contains(next, "stave generate control") {
		t.Fatalf("expected control generate recommendation, got: %s", next)
	}
}

func TestRecommendNextValidateEvaluateWhenOutputMissing(t *testing.T) {
	root := "/tmp/project"

	next := State{
		ProjectState: appstatus.ProjectState{
			Root:         root,
			Controls:     appstatus.Summary{Count: 1, HasLatest: true, Latest: time.Now().Add(-2 * time.Hour)},
			RawSnapshots: appstatus.Summary{},
			Observations: appstatus.Summary{Count: 2, HasLatest: true, Latest: time.Now().Add(-time.Hour)},
		},
	}.RecommendNext()
	if !strings.Contains(next, "stave validate") || !strings.Contains(next, "stave apply") {
		t.Fatalf("expected validate+apply recommendation, got: %s", next)
	}
}

func TestSaveAndLoadSessionState(t *testing.T) {
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "controls"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(project, "observations"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := projctx.SaveSession(project, []string{"apply", "--controls", "./controls"}); err != nil {
		t.Fatalf("saveSessionState: %v", err)
	}
	st, err := projctx.LoadSession(project)
	if err != nil {
		t.Fatalf("loadSessionState: %v", err)
	}
	if st == nil || !strings.Contains(st.LastCommand, "apply") {
		t.Fatalf("expected saved session command, got: %+v", st)
	}
}
