package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Confirm prompts the user with a y/N question on stderr and returns true
// only when they answer "y" or "yes" (case-insensitive). Uses bufio to read
// the full line, avoiding fmt.Scanln's whitespace-splitting behavior.
func Confirm(prompt string) bool {
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)

	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.ToLower(strings.TrimSpace(input))
	return input == "y" || input == "yes"
}
