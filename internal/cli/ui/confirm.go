package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// DefaultPrompter is the standard prompter using os.Stdin and os.Stderr.
var DefaultPrompter = NewPrompter(os.Stdin, os.Stderr)

// Prompter handles interactive user input.
type Prompter struct {
	scanner *bufio.Scanner
	out     io.Writer
}

// NewPrompter creates a Prompter that reads from r and writes to w.
func NewPrompter(r io.Reader, w io.Writer) *Prompter {
	return &Prompter{
		scanner: bufio.NewScanner(r),
		out:     w,
	}
}

// Confirm prompts the user with a y/N question and returns true only
// if they answer "y" or "yes" (case-insensitive).
func (p *Prompter) Confirm(prompt string) bool {
	fmt.Fprintf(p.out, "%s [y/N] ", prompt)

	if !p.scanner.Scan() {
		return false
	}

	input := strings.ToLower(strings.TrimSpace(p.scanner.Text()))
	return input == "y" || input == "yes"
}

// Confirm is a wrapper for DefaultPrompter.Confirm.
func Confirm(prompt string) bool {
	return DefaultPrompter.Confirm(prompt)
}
