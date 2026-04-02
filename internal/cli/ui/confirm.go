package ui

import (
	"bufio"
	"fmt"
	"io"
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
func (p *Prompter) Confirm(prompt string) bool {
	if p.autoConfirm {
		return true
	}

	fmt.Fprintf(p.out, "%s [y/N] ", prompt)

	if !p.scanner.Scan() {
		return false
	}

	input := strings.ToLower(strings.TrimSpace(p.scanner.Text()))
	return input == "y" || input == "yes"
}
