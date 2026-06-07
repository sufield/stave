package stave

import "testing"

func TestSanitizeSnapshot_MissingFileErrors(t *testing.T) {
	_, _, err := SanitizeSnapshot("/nonexistent/snapshot.json", "")
	if err == nil {
		t.Fatal("expected an error for a missing snapshot file")
	}
}
