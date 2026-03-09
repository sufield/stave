package status

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

type options struct {
	Dir    string
	Format string
}

// dirSummary and supporting helpers (status command).
type dirSummary struct {
	Count     int
	Latest    time.Time
	HasLatest bool
}

func summarizeFiles(dir string, exts ...string) (dirSummary, error) {
	var out dirSummary
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if len(exts) > 0 && !matchesExtension(e.Name(), exts) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out.Count++
		if !out.HasLatest || fi.ModTime().After(out.Latest) {
			out.Latest = fi.ModTime()
			out.HasLatest = true
		}
	}
	return out, nil
}

func matchesExtension(name string, exts []string) bool {
	for _, ext := range exts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func latestFileTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

type statusOutput struct {
	ProjectRoot   string                `json:"project_root"`
	LastSession   *projctx.SessionState `json:"last_session,omitempty"`
	Controls      dirSummary            `json:"controls"`
	RawSnapshots  dirSummary            `json:"snapshots_raw"`
	Observations  dirSummary            `json:"observations"`
	EvaluationOut bool                  `json:"evaluation_output"`
	NextCommand   string                `json:"next_command"`
}

// ProjectState captures project artifacts and timestamps for recommendation logic.
type ProjectState struct {
	Root         string
	Controls     dirSummary
	RawSnapshots dirSummary
	Observations dirSummary
	EvalTime     time.Time
	HasEval      bool
}

// RecommendNext returns the next best command for progressing the project.
func (s ProjectState) RecommendNext() string {
	raw := s.RawSnapshots
	obs := s.Observations
	ctl := s.Controls
	ctlDir := filepath.Join(s.Root, "controls")
	rawDir := filepath.Join(s.Root, "snapshots", "raw", "aws-s3")
	obsDir := filepath.Join(s.Root, "observations")

	if raw.Count > 0 && (obs.Count == 0 || s.isRawNewerThanObs()) {
		return fmt.Sprintf("stave ingest --profile aws-s3 --input %s --out %s", rawDir, obsDir)
	}
	if ctl.Count == 0 {
		return fmt.Sprintf("stave generate control --id CTL.S3.PUBLIC.901 --out %s", filepath.Join(ctlDir, "CTL.S3.PUBLIC.901.yaml"))
	}
	if obs.Count == 0 {
		return fmt.Sprintf("stave ingest --profile aws-s3 --input %s --out %s", rawDir, obsDir)
	}
	if s.needsReevaluation() {
		return fmt.Sprintf("stave validate --controls %s --observations %s && stave apply --controls %s --observations %s --format json > %s",
			ctlDir, obsDir, ctlDir, obsDir, filepath.Join(s.Root, "output", "evaluation.json"))
	}
	return fmt.Sprintf("stave diagnose --controls %s --observations %s --previous-output %s",
		ctlDir, obsDir, filepath.Join(s.Root, "output", "evaluation.json"))
}

func (s ProjectState) isRawNewerThanObs() bool {
	raw := s.RawSnapshots
	obs := s.Observations
	return raw.HasLatest &&
		obs.HasLatest &&
		raw.Latest.After(obs.Latest)
}

func (s ProjectState) needsReevaluation() bool {
	if !s.HasEval {
		return true
	}
	inputLatest := s.Controls.Latest
	obs := s.Observations
	if obs.HasLatest && obs.Latest.After(inputLatest) {
		inputLatest = obs.Latest
	}
	return inputLatest.After(s.EvalTime)
}

func run(cmd *cobra.Command, opts *options) error {
	root, err := projctx.DetectProjectRoot(opts.Dir)
	if err != nil {
		return ui.WithNextCommand(err, "stave init")
	}

	out, err := buildOutput(root)
	if err != nil {
		return err
	}
	format, err := compose.ResolveFormatValue(cmd, opts.Format)
	if err != nil {
		return err
	}
	if format.IsJSON() {
		return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
	}
	return writeText(cmd.OutOrStdout(), out)
}

func buildOutput(root string) (statusOutput, error) {
	controls, err := summarizeFiles(filepath.Join(root, "controls"), ".yaml", ".yml")
	if err != nil {
		return statusOutput{}, err
	}
	raw, err := summarizeFiles(filepath.Join(root, "snapshots", "raw"), ".json")
	if err != nil {
		return statusOutput{}, err
	}
	obs, err := summarizeFiles(filepath.Join(root, "observations"), ".json")
	if err != nil {
		return statusOutput{}, err
	}
	evalPath := filepath.Join(root, "output", "evaluation.json")
	evalTime, hasEval := latestFileTime(evalPath)

	last, err := projctx.LoadSessionState(root)
	if err != nil {
		return statusOutput{}, err
	}

	state := ProjectState{
		Root:         root,
		Controls:     controls,
		RawSnapshots: raw,
		Observations: obs,
		EvalTime:     evalTime,
		HasEval:      hasEval,
	}
	out := statusOutput{
		ProjectRoot:   root,
		LastSession:   last,
		Controls:      controls,
		RawSnapshots:  raw,
		Observations:  obs,
		EvaluationOut: hasEval,
		NextCommand:   state.RecommendNext(),
	}
	return out, nil
}

func writeText(w io.Writer, out statusOutput) error {
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("Summary\n-------\n")
	writef("Project: %s\n", out.ProjectRoot)
	if out.LastSession != nil {
		writef("Last command: %s (%s)\n", out.LastSession.LastCommand, out.LastSession.WhenUTC.Format(time.RFC3339))
	}
	writef("Artifacts:\n")
	writef("  - controls: %d\n", out.Controls.Count)
	writef("  - snapshots/raw: %d\n", out.RawSnapshots.Count)
	writef("  - observations: %d\n", out.Observations.Count)
	writef("  - output/evaluation.json: %v\n", out.EvaluationOut)
	if err != nil {
		return err
	}
	next := ui.SeverityLabel("info", fmt.Sprintf("Next: %s", out.NextCommand), w)
	writef("\n%s\n", next)
	return err
}

func NextCommandForProject(projectRoot string) (string, error) {
	out, err := buildOutput(projectRoot)
	if err != nil {
		return "", err
	}
	return out.NextCommand, nil
}
