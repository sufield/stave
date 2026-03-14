package status

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/projctx"
)

func TestRecommendNextCreateControlWhenMissing(t *testing.T) {
	root := "/tmp/project"
	compiled := Summary{}
	raw := Summary{}
	obs := Summary{Count: 1, HasLatest: true, Latest: time.Now().Add(-2 * time.Hour)}

	next := State{
		Root:         root,
		Controls:     compiled,
		RawSnapshots: raw,
		Observations: obs,
		EvalTime:     time.Time{},
		HasEval:      false,
	}.RecommendNext()
	if !strings.Contains(next, "stave generate control") {
		t.Fatalf("expected control generate recommendation, got: %s", next)
	}
}

func TestRecommendNextValidateEvaluateWhenOutputMissing(t *testing.T) {
	root := "/tmp/project"
	compiled := Summary{Count: 1, HasLatest: true, Latest: time.Now().Add(-2 * time.Hour)}
	raw := Summary{}
	obs := Summary{Count: 2, HasLatest: true, Latest: time.Now().Add(-time.Hour)}

	next := State{
		Root:         root,
		Controls:     compiled,
		RawSnapshots: raw,
		Observations: obs,
		EvalTime:     time.Time{},
		HasEval:      false,
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
