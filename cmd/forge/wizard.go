package forge

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// wizard provides sequential text-based prompts via bufio.Scanner.
type wizard struct {
	scanner *bufio.Scanner
	out     io.Writer
}

func newWizard(in io.Reader, out io.Writer) *wizard {
	return &wizard{
		scanner: bufio.NewScanner(in),
		out:     out,
	}
}

// readLine prompts for a single line of text input.
func (w *wizard) readLine(prompt string) string {
	fmt.Fprintf(w.out, "%s ", prompt)
	if w.scanner.Scan() {
		return strings.TrimSpace(w.scanner.Text())
	}
	return ""
}

// readLineDefault prompts with a default value shown in brackets.
func (w *wizard) readLineDefault(prompt, defaultVal string) string {
	fmt.Fprintf(w.out, "%s [%s]: ", prompt, defaultVal)
	if w.scanner.Scan() {
		val := strings.TrimSpace(w.scanner.Text())
		if val == "" {
			return defaultVal
		}
		return val
	}
	return defaultVal
}

// selectOption shows a numbered list and returns the selected value.
func (w *wizard) selectOption(prompt string, options []string) string {
	fmt.Fprintln(w.out, prompt)
	for i, opt := range options {
		fmt.Fprintf(w.out, "  [%d] %s\n", i+1, opt)
	}
	for {
		input := w.readLine(">")
		// Try as number first.
		var idx int
		if _, err := fmt.Sscanf(input, "%d", &idx); err == nil && idx >= 1 && idx <= len(options) {
			return options[idx-1]
		}
		// Try as exact match.
		for _, opt := range options {
			if strings.EqualFold(input, opt) {
				return opt
			}
		}
		fmt.Fprintf(w.out, "  Invalid selection. Enter 1-%d or type the value.\n", len(options))
	}
}

// selectOptionWithDescriptions shows options with descriptions.
func (w *wizard) selectOptionWithDescriptions(prompt string, options []string, descriptions []string) string {
	fmt.Fprintln(w.out, prompt)
	for i, opt := range options {
		desc := ""
		if i < len(descriptions) {
			desc = descriptions[i]
		}
		if desc != "" {
			fmt.Fprintf(w.out, "  [%d] %-22s %s\n", i+1, opt, desc)
		} else {
			fmt.Fprintf(w.out, "  [%d] %s\n", i+1, opt)
		}
	}
	for {
		input := w.readLine(">")
		var idx int
		if _, err := fmt.Sscanf(input, "%d", &idx); err == nil && idx >= 1 && idx <= len(options) {
			return options[idx-1]
		}
		for _, opt := range options {
			if strings.EqualFold(input, opt) {
				return opt
			}
		}
		fmt.Fprintf(w.out, "  Invalid selection. Enter 1-%d.\n", len(options))
	}
}

// confirm asks a yes/no question. Default is yes.
func (w *wizard) confirm(prompt string) bool {
	input := w.readLineDefault(prompt, "Y")
	return strings.HasPrefix(strings.ToUpper(input), "Y")
}

// controlIDPattern validates the CTL.SERVICE.TOPIC.NNN format.
var controlIDPattern = regexp.MustCompile(`^CTL\.[A-Z][A-Z0-9]*\.[A-Z][A-Z0-9]*\.\d{3}$`)

// readControlID prompts for a control ID with inline validation.
func (w *wizard) readControlID() string {
	for {
		id := w.readLine("Control ID (e.g. CTL.S3.TAGS.001):")
		id = strings.ToUpper(id)
		if controlIDPattern.MatchString(id) {
			return id
		}
		fmt.Fprintln(w.out, "  Invalid format. Expected: CTL.<SERVICE>.<TOPIC>.<NNN>")
	}
}
