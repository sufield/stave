package prompt

import (
	"fmt"
	"io"
	"runtime"

	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func (r *Runner) write(cfg Config, out PromptOutput) error {
	w := cfg.Stdout
	if cfg.Quiet && !cfg.Format.IsJSON() {
		w = io.Discard
	}

	if cfg.Format.IsJSON() {
		findingIDs := make([]string, len(out.FindingIDs))
		for i, id := range out.FindingIDs {
			findingIDs[i] = string(id)
		}
		res := Result{
			Prompt:     out.Rendered,
			FindingIDs: findingIDs,
			AssetID:    out.AssetID,
		}
		return jsonutil.WriteIndented(w, res)
	}

	if _, err := fmt.Fprint(w, out.Rendered); err != nil {
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
