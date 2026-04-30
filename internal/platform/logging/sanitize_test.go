package logging

import (
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/sufield/stave/internal/sanitize"
)

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		path      string
		fullPaths bool
		expected  string
	}{
		{"/home/user/secrets.json", false, "secrets.json"},
		{"/home/user/secrets.json", true, "/home/user/secrets.json"},
		{"file.txt", false, "file.txt"},
		{"file.txt", true, "file.txt"},
		{"/a/b/c/d.yaml", false, "d.yaml"},
	}

	for _, tt := range tests {
		got := SanitizePath(tt.path, tt.fullPaths)
		if got != tt.expected {
			t.Errorf("SanitizePath(%q, %v) = %q, want %q", tt.path, tt.fullPaths, got, tt.expected)
		}
	}
}

func Test_truncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "he..."},
		{"hello world", 8, "hello..."},
		{"hi", 2, "hi"},
		{"hello", 3, "hel"},
		{"", 5, ""},
		{"你好世界", 3, "你好世"},
		{"你好世界啊", 4, "你..."},
		{"hello", 0, ""},
	}

	for _, tt := range tests {
		got := truncateString(tt.input, tt.maxLen)
		if got != tt.expected {
			t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.expected)
		}
		if !utf8.ValidString(got) {
			t.Errorf("truncateString(%q, %d) produced invalid UTF-8: %q", tt.input, tt.maxLen, got)
		}
	}
}

func TestSanitizeArgs(t *testing.T) {
	tests := []struct {
		args     []string
		expected []string
	}{
		{
			[]string{"--config", "file.yaml"},
			[]string{"--config", "file.yaml"},
		},
		{
			[]string{"--password", "secret123"},
			[]string{"--password", sanitize.SanitizedValue},
		},
		{
			[]string{"--api-key=my-secret-key"},
			[]string{"--api-key=" + sanitize.SanitizedValue},
		},
		{
			[]string{"--token", "abc123", "--path", "/home"},
			[]string{"--token", sanitize.SanitizedValue, "--path", "/home"},
		},
		{
			[]string{"-v", "--secret-file", "/path/to/secret"},
			[]string{"-v", "--secret-file", sanitize.SanitizedValue},
		},
		{
			[]string{"--file=mykey.txt"},
			[]string{"--file=mykey.txt"},
		},
		{
			// Per Phase 11 P11.4 task 3: aggressive redaction. The
			// value position after a sensitive flag is always
			// redacted regardless of whether it looks like another
			// flag. Tradeoff: an operator who passed
			// `--token --path /tmp` (intending --token to take no
			// value) now sees --path redacted; the alternative
			// (leaking a real password that legitimately starts
			// with `-`) is materially worse.
			[]string{"--token", "--path", "/tmp"},
			[]string{"--token", sanitize.SanitizedValue, "/tmp"},
		},
		{
			[]string{"--token", "-1"},
			[]string{"--token", sanitize.SanitizedValue},
		},
		{
			// Sensitive flag with value starting with `-`: previously
			// passed through unredacted because isLikelyFlagToken
			// short-circuited the redaction. Now redacted.
			[]string{"--password", "-very-secret-pass"},
			[]string{"--password", sanitize.SanitizedValue},
		},
		{
			// Sensitive flag as the trailing arg: structurally
			// missing value. Render as "[SANITIZED:missing]" so the
			// log line still communicates the shape.
			[]string{"--ok", "--api-key"},
			[]string{"--ok", "--api-key " + sanitize.SanitizedValue + ":missing"},
		},
		{
			[]string{"--ACCESS-TOKEN", "abc123"},
			[]string{"--ACCESS-TOKEN", sanitize.SanitizedValue},
		},
	}

	for _, tt := range tests {
		got := SanitizeArgs(tt.args)
		if !reflect.DeepEqual(got, tt.expected) {
			t.Errorf("SanitizeArgs(%v) = %v, want %v", tt.args, got, tt.expected)
		}
	}
}

func TestIsSensitiveArg(t *testing.T) {
	tests := []struct {
		arg      string
		expected bool
	}{
		{"--token", true},
		{"--api-key", true},
		{"--api_key", true},
		{"--accessToken", false},  // camelCase without separator — not matched by token splitting
		{"--access-token", true},  // hyphenated — "token" token matches
		{"--authorization", true}, // exact match in sensitiveArgNames
		{"--private-key", true},   // "key" token matches
		{"--author-name", false},  // "author" is not a sensitive token
		{"--file=mykey.txt", false},
		{"--monkey", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isSensitiveKey(tt.arg)
		if got != tt.expected {
			t.Errorf("isSensitiveKey(%q) = %v, want %v", tt.arg, got, tt.expected)
		}
	}
}
