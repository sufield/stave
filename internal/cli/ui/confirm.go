package ui

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Prompter handles interactive user input.
type Prompter struct {
	scanner     *bufio.Scanner
	out         io.Writer
	autoConfirm bool
}

// NewPrompter creates a Prompter that reads from r and writes to w.
func NewPrompter(r io.Reader, w io.Writer) *Prompter {
	return &Prompter{
		scanner: bufio.NewScanner(r),
		out:     w,
	}
}

// NewAutoConfirmPrompter creates a Prompter that automatically confirms all prompts.
// Use this when --yes is set or stdin is not a TTY.
func NewAutoConfirmPrompter(w io.Writer) *Prompter {
	return &Prompter{
		out:         w,
		autoConfirm: true,
	}
}

// Confirm prompts the user with a y/N question and returns true only
// if they answer "y" or "yes" (case-insensitive).
// When auto-confirm is enabled (via --yes or non-TTY), returns true immediately.
//
// A scanner I/O failure (broken pipe on the stdin reader, terminal
// closed mid-prompt) is treated as a rejection like clean EOF, but
// the underlying error is logged at warn level so the silent
// "rejected by user" outcome does not mask a real plumbing failure.
// The earlier shape returned false on Scan()==false without checking
// Err(), so a corrupted stdin and a deliberate "no" looked
// identical to operators reading the audit log.
func (p *Prompter) Confirm(prompt string) bool {
	if p.autoConfirm {
		return true
	}

	fmt.Fprintf(p.out, "%s [y/N] ", prompt)

	if !p.scanner.Scan() {
		if scanErr := p.scanner.Err(); scanErr != nil {
			slog.Warn("ui.Prompter: stdin scan failed; treating as rejection",
				"error", scanErr)
		}
		return false
	}

	trimmed := strings.TrimSpace(p.scanner.Text())
	return strings.EqualFold(trimmed, "y") || strings.EqualFold(trimmed, "yes")
}
