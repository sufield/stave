package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestSuggestFlagParseError_AddsSuggestionForUnknownLongFlag(t *testing.T) {
	candidates := []string{"--max-unsafe", "--controls"}

	err := SuggestFlagParseError(errors.New("unknown flag: --max-gap"), candidates)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unknown flag: --max-gap") {
		t.Fatalf("missing original message: %q", msg)
	}
	if !strings.Contains(msg, `Did you mean "--max-unsafe"?`) {
		t.Fatalf("missing suggestion: %q", msg)
	}
}

func TestSuggestFlagParseError_AddsSuggestionForUnknownShorthand(t *testing.T) {
	candidates := []string{"--verbose", "-v"}

	err := SuggestFlagParseError(errors.New("unknown shorthand flag: 'x' in -x"), candidates)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), `Did you mean "-v"?`) {
		t.Fatalf("expected shorthand suggestion, got: %q", err.Error())
	}
}

func TestSuggestFlagParseError_NoSuggestionForDistantFlag(t *testing.T) {
	candidates := []string{"--controls", "--observations"}

	err := SuggestFlagParseError(errors.New("unknown flag: --zzz"), candidates)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Fatalf("unexpected suggestion for distant flag: %q", err.Error())
	}
}

func TestSuggestFlagParseError_NilError(t *testing.T) {
	if err := SuggestFlagParseError(nil, []string{"--foo"}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestSuggestFlagParseError_NoSuggestionForUnrelatedMatch(t *testing.T) {
	candidates := []string{"--helpful", "--version"}
	err := SuggestFlagParseError(errors.New("unknown flag: --max-gap"), candidates)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "Did you mean") {
		t.Fatalf("unexpected suggestion for unrelated flag: %q", err.Error())
	}
}

func TestExtractUnknownFlag_ShorthandInFormat(t *testing.T) {
	flag := extractUnknownFlag("unknown shorthand flag: 'x' in -x")
	if flag != "-x" {
		t.Fatalf("expected -x, got %q", flag)
	}
}

func TestExtractUnknownFlag_LongQuotedFormat(t *testing.T) {
	flag := extractUnknownFlag(`unknown flag: '--max-gap'`)
	if flag != "--max-gap" {
		t.Fatalf("expected --max-gap, got %q", flag)
	}
}

func TestExtractUnknownFlag_ShorthandQuotedWithoutIn(t *testing.T) {
	flag := extractUnknownFlag(`unknown shorthand flag: 'x'`)
	if flag != "-x" {
		t.Fatalf("expected -x, got %q", flag)
	}
}

func TestExtractUnknownFlag_LastWordFallback(t *testing.T) {
	flag := extractUnknownFlag("some unexpected error format --oops")
	if flag != "--oops" {
		t.Fatalf("expected --oops, got %q", flag)
	}
}

func TestExtractUnknownFlag_NoFlagToken(t *testing.T) {
	flag := extractUnknownFlag("completely unrelated error message")
	if flag != "" {
		t.Fatalf("expected empty, got %q", flag)
	}
}

func TestExtractUnknownFlag_DoubleQuotedToken(t *testing.T) {
	flag := extractUnknownFlag(`unknown flag: "--verbose"`)
	if flag != "--verbose" {
		t.Fatalf("expected --verbose, got %q", flag)
	}
}
