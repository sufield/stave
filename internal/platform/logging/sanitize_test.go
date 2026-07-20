package logging

import (
	"testing"
	"unicode/utf8"
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
