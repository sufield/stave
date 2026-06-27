package logging

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/sanitize"
)

func TestBugHunt_SanitizeArgs_ConsecutiveSingleDash(t *testing.T) {
	t.Parallel()

	// In the original code, consecutive sensitive flags where the second one
	// starts with a single dash (e.g. "-password") were not recognized as flags
	// in the look-ahead because of strings.HasPrefix(args[i+1], "--").
	// As a result, the second flag name was treated as the value of the first,
	// and the actual secret value was exposed.
	input := []string{"--token", "-password", "mysecret"}
	expected := []string{
		"--token " + sanitize.SanitizedValue + ":missing",
		"-password",
		sanitize.SanitizedValue,
	}

	got := SanitizeArgs(input)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("SanitizeArgs(%v) = %v, want %v", input, got, expected)
	}

	// Also test when both use single dashes
	input2 := []string{"-token", "-password", "mysecret2"}
	expected2 := []string{
		"-token " + sanitize.SanitizedValue + ":missing",
		"-password",
		sanitize.SanitizedValue,
	}

	got2 := SanitizeArgs(input2)
	if !reflect.DeepEqual(got2, expected2) {
		t.Errorf("SanitizeArgs(%v) = %v, want %v", input2, got2, expected2)
	}
}
