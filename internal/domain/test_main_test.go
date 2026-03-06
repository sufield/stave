package domain

import (
	"os"
	"testing"

	"github.com/sufield/stave/internal/testutil"
)

// yamlPredicateParser is a package-level parser function shared by domain
// tests that exercise any_match controls.
var yamlPredicateParser = testutil.YAMLPredicateParser()

// TestMain runs domain-layer tests.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
