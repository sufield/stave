package docsverify

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// ExtractedCommand represents a CLI command found in a Markdown code block.
type ExtractedCommand struct {
	File        string
	Line        int
	Lang        string
	Command     string
	Skip        bool
	SkipReason  string
	ExpectError bool
}

// ExtractCommands parses a Markdown file and returns all code blocks
// matching the given language tags that contain a stave CLI invocation.
func ExtractCommands(content []byte, file string, langs []string) ([]ExtractedCommand, error) {
	langSet := make(map[string]bool, len(langs))
	for _, l := range langs {
		langSet[l] = true
	}

	var commands []ExtractedCommand
	scanner := bufio.NewScanner(bytes.NewReader(content))

	var (
		inBlock    bool
		blockLang  string
		blockStart int
		blockLines []string
		lineNum    int
	)

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if !inBlock {
			if after, ok := strings.CutPrefix(line, "```"); ok {
				lang := strings.TrimSpace(after)
				if langSet[lang] {
					inBlock = true
					blockLang = lang
					blockStart = lineNum + 1
					blockLines = blockLines[:0]
				}
			}
			continue
		}

		if line == "```" {
			cmds := parseBlock(blockLines, file, blockStart, blockLang)
			commands = append(commands, cmds...)
			inBlock = false
			blockLang = ""
			blockLines = nil
			continue
		}

		blockLines = append(blockLines, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan markdown: %w", err)
	}
	return commands, nil
}

func parseBlock(lines []string, file string, startLine int, lang string) []ExtractedCommand {
	var (
		skip        bool
		skipReason  string
		expectError bool
	)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, "doctest:skip"); idx >= 0 {
			skip = true
			if after := strings.Index(trimmed[idx:], "—"); after >= 0 {
				skipReason = strings.TrimSpace(trimmed[idx+after:])
			} else if after := strings.Index(trimmed[idx:], "--"); after >= 0 {
				skipReason = strings.TrimSpace(trimmed[idx+after:])
			} else {
				skipReason = "doctest:skip"
			}
		}
		if strings.Contains(trimmed, "doctest:expect-error") {
			expectError = true
		}
	}

	var commands []ExtractedCommand
	var continuation string
	contStart := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		trimmed = strings.TrimPrefix(trimmed, "$ ")

		if continuation != "" {
			continuation += " " + trimmed
		} else {
			continuation = trimmed
			contStart = startLine + i
		}

		if before, ok := strings.CutSuffix(continuation, "\\"); ok {
			continuation = before
			continuation = strings.TrimRight(continuation, " ")
			continue
		}

		cmd := stripInlineComment(continuation)
		cmdLine := contStart
		continuation = ""

		if !isStaveCommand(cmd) {
			continue
		}

		ec := ExtractedCommand{
			File:        file,
			Line:        cmdLine,
			Lang:        lang,
			Command:     cmd,
			ExpectError: expectError,
			Skip:        skip,
			SkipReason:  skipReason,
		}

		if !skip && hasPipeOrRedirect(cmd) {
			ec.Skip = true
			ec.SkipReason = "contains pipe or redirect"
		}

		commands = append(commands, ec)
	}

	return commands
}

func isStaveCommand(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 1 {
		return false
	}
	if fields[0] != "stave" {
		return false
	}
	// "stave := ..." is Go, not CLI
	if len(fields) > 1 && fields[1] == ":=" {
		return false
	}
	return true
}

func stripInlineComment(cmd string) string {
	if before, _, ok := strings.Cut(cmd, " #"); ok {
		return strings.TrimRight(before, " ")
	}
	return cmd
}

func hasPipeOrRedirect(cmd string) bool {
	for _, ch := range cmd {
		if ch == '|' || ch == '>' || ch == '<' {
			return true
		}
	}
	return false
}
