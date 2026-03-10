package cmdutil

import (
	"testing"
)

func TestParseShellTokens(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "single token",
			input: "apply",
			want:  []string{"apply"},
		},
		{
			name:  "simple whitespace split",
			input: "apply --controls ./controls",
			want:  []string{"apply", "--controls", "./controls"},
		},
		{
			name:  "multiple spaces between tokens",
			input: "apply   --controls   ./controls",
			want:  []string{"apply", "--controls", "./controls"},
		},
		{
			name:  "leading and trailing whitespace",
			input: "  apply --controls ./controls  ",
			want:  []string{"apply", "--controls", "./controls"},
		},
		{
			name:  "tab separator",
			input: "apply\t--controls\t./controls",
			want:  []string{"apply", "--controls", "./controls"},
		},
		// Single-quote tests
		{
			name:  "single-quoted argument with spaces",
			input: `apply --controls 'path with spaces/controls'`,
			want:  []string{"apply", "--controls", "path with spaces/controls"},
		},
		{
			name:  "single-quoted preserves double quote",
			input: `'he said "hello"'`,
			want:  []string{`he said "hello"`},
		},
		{
			name:  "single-quoted preserves backslash literally",
			input: `'no\nescape'`,
			want:  []string{`no\nescape`},
		},
		{
			name:  "empty single-quoted string produces empty token",
			input: `before '' after`,
			want:  []string{"before", "", "after"},
		},
		// Double-quote tests
		{
			name:  "double-quoted argument with spaces",
			input: `apply --controls "path with spaces/controls"`,
			want:  []string{"apply", "--controls", "path with spaces/controls"},
		},
		{
			name:  "double-quoted escaped double quote",
			input: `"he said \"hello\""`,
			want:  []string{`he said "hello"`},
		},
		{
			name:  "double-quoted escaped backslash",
			input: `"a\\b"`,
			want:  []string{`a\b`},
		},
		{
			name:  "double-quoted newline escape",
			input: `"line1\nline2"`,
			want:  []string{"line1\nline2"},
		},
		{
			name:  "double-quoted tab escape",
			input: `"col1\tcol2"`,
			want:  []string{"col1\tcol2"},
		},
		{
			name:  "double-quoted carriage-return escape",
			input: `"cr\rend"`,
			want:  []string{"cr\rend"},
		},
		{
			name:  "double-quoted unknown escape preserves both chars",
			input: `"\q"`,
			want:  []string{`\q`},
		},
		{
			name:  "empty double-quoted string produces empty token",
			input: `before "" after`,
			want:  []string{"before", "", "after"},
		},
		// Backslash outside quotes
		{
			name:  "backslash escapes space outside quotes",
			input: `path\ with\ spaces`,
			want:  []string{"path with spaces"},
		},
		{
			name:  "backslash escapes special char outside quotes",
			input: `apply --flag value\=with\=equals`,
			want:  []string{"apply", "--flag", "value=with=equals"},
		},
		// Adjacent span concatenation
		{
			name:  "adjacent quoted spans merge into one token",
			input: `"path/"'with spaces'"/more"`,
			want:  []string{"path/with spaces/more"},
		},
		{
			name:  "unquoted then single-quoted without space",
			input: `pre'fix suffix'`,
			want:  []string{"prefix suffix"},
		},
		{
			name:  "double-quoted then unquoted without space",
			input: `"pre"fix`,
			want:  []string{"prefix"},
		},
		// Realistic alias expansion cases
		{
			name:  "alias with quoted flag value containing spaces",
			input: `apply --controls "path with spaces/controls" --observations obs`,
			want:  []string{"apply", "--controls", "path with spaces/controls", "--observations", "obs"},
		},
		{
			name:  "alias with multiple flags",
			input: `apply --controls ./controls --observations ./observations --format json`,
			want:  []string{"apply", "--controls", "./controls", "--observations", "./observations", "--format", "json"},
		},
		// Error cases
		{
			name:    "unclosed single quote",
			input:   `apply 'unclosed`,
			wantErr: true,
		},
		{
			name:    "unclosed double quote",
			input:   `apply "unclosed`,
			wantErr: true,
		},
		{
			name:    "trailing backslash",
			input:   `apply \`,
			wantErr: true,
		},
		{
			name:    "trailing backslash after token",
			input:   `apply --flag \`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseShellTokens(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseShellTokens(%q): expected error, got nil (tokens=%v)", tt.input, got)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseShellTokens(%q): unexpected error: %v", tt.input, err)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("ParseShellTokens(%q)\n  got  %v (len=%d)\n  want %v (len=%d)",
					tt.input, got, len(got), tt.want, len(tt.want))
				return
			}

			for i, tok := range got {
				if tok != tt.want[i] {
					t.Errorf("ParseShellTokens(%q)[%d] = %q, want %q", tt.input, i, tok, tt.want[i])
				}
			}
		})
	}
}
