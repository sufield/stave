package prompt

import (
	"fmt"
	"io"
	"runtime"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// WriteOutput renders a PromptOutput to the writer in the given format.
func WriteOutput(w, stderr io.Writer, out PromptOutput, format appcontracts.OutputFormat, quiet bool) error {
	if quiet && !format.IsMachineReadable() {
		w = io.Discard
	}

	if format.IsJSON() {
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
	writeClipboardHint(stderr, quiet)
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
