package fix

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/capabilities"
)

// TestMain configures the package-level injection slots that
// production code wires through NewApp.
func TestMain(m *testing.M) {
	capabilities.Configure(pack.MustNewLibrary())
	m.Run()
}
