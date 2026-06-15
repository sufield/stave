package strutil

import (
	"strings"
	"testing"
)

func TestToLowerTrim_EquivalentToToLowerTrimSpace(t *testing.T) {
	t.Parallel()
	cases := []string{
		"",
		"already-lower",
		"  spaced  ",
		"MixedCase",
		"\tTABS\n",
		"HIGH",
		"s3:GetObject",
		"ÉCOLE",       // non-ASCII upper-case — fast path must NOT skip lowering
		"café",        // non-ASCII already lower
		"  Ünïcödé  ", // non-ASCII + whitespace
		"   ",         // whitespace only -> ""
	}
	for _, in := range cases {
		got := ToLowerTrim(in)
		want := strings.ToLower(strings.TrimSpace(in)) // the canonical form it optimizes
		if got != want {
			t.Errorf("ToLowerTrim(%q) = %q, want %q", in, got, want)
		}
	}
}
