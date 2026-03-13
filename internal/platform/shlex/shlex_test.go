package shlex

import (
	"errors"
	"testing"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr error
	}{
		{name: "empty", input: "", want: nil},
		{name: "single token", input: "hello", want: []string{"hello"}},
		{name: "whitespace split", input: "a b c", want: []string{"a", "b", "c"}},
		{name: "tabs and newlines", input: "a\tb\nc", want: []string{"a", "b", "c"}},
		{name: "leading trailing space", input: "  a  ", want: []string{"a"}},
		// Single quotes
		{name: "single-quoted spaces", input: "'a b'", want: []string{"a b"}},
		{name: "single-quoted backslash literal", input: `'a\nb'`, want: []string{`a\nb`}},
		{name: "empty single quotes", input: "''", want: []string{""}},
		// Double quotes
		{name: "double-quoted spaces", input: `"a b"`, want: []string{"a b"}},
		{name: "double-quoted escaped quote", input: `"a\"b"`, want: []string{`a"b`}},
		{name: "double-quoted escaped backslash", input: `"a\\b"`, want: []string{`a\b`}},
		{name: "double-quoted newline escape", input: `"a\nb"`, want: []string{"a\nb"}},
		{name: "double-quoted tab escape", input: `"a\tb"`, want: []string{"a\tb"}},
		{name: "double-quoted cr escape", input: `"a\rb"`, want: []string{"a\rb"}},
		{name: "double-quoted unknown escape", input: `"a\qb"`, want: []string{`a\qb`}},
		{name: "empty double quotes", input: `""`, want: []string{""}},
		// Backslash outside quotes
		{name: "backslash-escaped space", input: `a\ b`, want: []string{"a b"}},
		{name: "backslash-escaped char", input: `a\=b`, want: []string{"a=b"}},
		// Adjacent spans
		{name: "adjacent quoted spans", input: `"a"'b'c`, want: []string{"abc"}},
		// Unicode
		{name: "unicode tokens", input: "héllo wörld", want: []string{"héllo", "wörld"}},
		{name: "unicode in single quotes", input: "'üñíçødê path'", want: []string{"üñíçødê path"}},
		{name: "unicode in double quotes", input: `"日本語 パス"`, want: []string{"日本語 パス"}},
		{name: "backslash-escaped unicode", input: `a\ ñ`, want: []string{"a ñ"}},
		// Errors
		{name: "unclosed single quote", input: "'open", wantErr: ErrUnclosedSingleQuote},
		{name: "unclosed double quote", input: `"open`, wantErr: ErrUnclosedDoubleQuote},
		{name: "trailing backslash", input: `a\`, wantErr: ErrTrailingBackslash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Split(tt.input)

			if tt.wantErr != nil {
				if err == nil {
					t.Fatalf("Split(%q): expected error, got nil (tokens=%v)", tt.input, got)
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Split(%q): got error %v, want %v", tt.input, err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Split(%q): unexpected error: %v", tt.input, err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("Split(%q)\n  got  %v (len=%d)\n  want %v (len=%d)",
					tt.input, got, len(got), tt.want, len(tt.want))
			}

			for i, tok := range got {
				if tok != tt.want[i] {
					t.Errorf("Split(%q)[%d] = %q, want %q", tt.input, i, tok, tt.want[i])
				}
			}
		})
	}
}
