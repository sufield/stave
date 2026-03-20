package domain

import (
	"os"
	"testing"
)

// TestMain runs domain-layer tests.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
