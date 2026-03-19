package prompt

import (
	"fmt"
	"io"
	"runtime"

	promptout "github.com/sufield/stave/internal/adapters/output/prompt"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func (r *Runner) write(cfg Config, rendered string, data promptout.PromptData) error {
	out := cfg.Stdout
	if cfg.Quiet && !cfg.Format.IsJSON() {
		out = io.Discard
	}

	if cfg.Format.IsJSON() {
		findingIDs := make([]string, len(data.Findings))
		for i, f := range data.Findings {
			findingIDs[i] = string(f.ControlID)
		}
		res := Result{
			Prompt:     rendered,
			FindingIDs: findingIDs,
			AssetID:    data.AssetID,
		}
		return jsonutil.WriteIndented(out, res)
	}

	if _, err := fmt.Fprint(out, rendered); err != nil {
		return err
	}
	writeClipboardHint(cfg.Stderr, cfg.Quiet)
	return nil
}

func writeClipboardHint(w io.Writer, quiet bool) {
	if quiet {
		return
	}
	var tool string
	switch runtime.GOOS {
	case "darwin":
		tool = "pbcopy"
	case "linux":
		tool = "xclip -selection clipboard"
	default:
		return
	}
	fmt.Fprintf(w, "Hint: pipe to clipboard with:\n  stave prompt from-finding ... | %s\n", tool)
}
