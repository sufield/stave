// Package shlex provides POSIX-like shell word splitting with support
// for single quotes, double quotes, and backslash escapes.
package shlex

import (
	"errors"
	"strings"
)

// Sentinel errors for malformed shell input.
var (
	ErrUnclosedSingleQuote = errors.New("unclosed single quote")
	ErrUnclosedDoubleQuote = errors.New("unclosed double quote")
	ErrTrailingBackslash   = errors.New("trailing backslash")
)

// Split parses s into tokens using POSIX-like shell quoting rules.
//
// Rules applied:
//   - Unquoted whitespace (space, tab, newline, carriage return) separates tokens.
//   - Single-quoted text ('...') is fully literal; no escape sequences are
//     recognised inside single quotes.
//   - Double-quoted text ("...") supports the backslash escapes \", \\, \n, \t,
//     and \r. Any other backslash sequence preserves both characters.
//   - A backslash outside any quoting context escapes the immediately following
//     character.
//   - Adjacent quoted or unquoted spans with no intervening whitespace are
//     concatenated into a single token.
func Split(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}

	var tokens []string
	var builder strings.Builder

	runes := []rune(s)
	inToken := false

	for i := 0; i < len(runes); {
		ch := runes[i]

		switch ch {
		case '\'':
			inToken = true
			next, err := parseSingleQuoted(runes, i+1, &builder)
			if err != nil {
				return nil, err
			}
			i = next

		case '"':
			inToken = true
			next, err := parseDoubleQuoted(runes, i+1, &builder)
			if err != nil {
				return nil, err
			}
			i = next

		case '\\':
			if i+1 >= len(runes) {
				return nil, ErrTrailingBackslash
			}
			inToken = true
			i++
			builder.WriteRune(runes[i])
			i++

		case ' ', '\t', '\n', '\r':
			if inToken {
				tokens = append(tokens, builder.String())
				builder.Reset()
				inToken = false
			}
			i++

		default:
			inToken = true
			builder.WriteRune(ch)
			i++
		}
	}

	if inToken {
		tokens = append(tokens, builder.String())
	}

	return tokens, nil
}

func parseSingleQuoted(runes []rune, start int, builder *strings.Builder) (int, error) {
	i := start
	for {
		if i >= len(runes) {
			return 0, ErrUnclosedSingleQuote
		}
		if runes[i] == '\'' {
			return i + 1, nil
		}
		builder.WriteRune(runes[i])
		i++
	}
}

func parseDoubleQuoted(runes []rune, start int, builder *strings.Builder) (int, error) {
	i := start
	for {
		if i >= len(runes) {
			return 0, ErrUnclosedDoubleQuote
		}
		if runes[i] == '"' {
			return i + 1, nil
		}
		if runes[i] == '\\' && i+1 < len(runes) {
			i++
			switch runes[i] {
			case '"', '\\':
				builder.WriteRune(runes[i])
			case 'n':
				builder.WriteRune('\n')
			case 't':
				builder.WriteRune('\t')
			case 'r':
				builder.WriteRune('\r')
			default:
				builder.WriteRune('\\')
				builder.WriteRune(runes[i])
			}
		} else {
			builder.WriteRune(runes[i])
		}
		i++
	}
}
