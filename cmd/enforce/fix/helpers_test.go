package fix

import (
	"testing"

	"github.com/sufield/stave/internal/testutil"
)

func testdataDir(t *testing.T, name string) string {
	t.Helper()
	return testutil.E2EDir(t, name)
}
