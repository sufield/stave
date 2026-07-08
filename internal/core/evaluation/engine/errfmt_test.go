package engine

import (
	"testing"
	"unicode"
)

func TestErrClockMissing_IsLowercase(t *testing.T) {
	t.Parallel()
	msg := ErrClockMissing.Error()
	if r := []rune(msg); unicode.IsUpper(r[0]) {
		t.Errorf("sentinel error starts with uppercase: %q", msg)
	}
}
