package cmd

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/capabilities"
)

// TestMain configures the package-level injection slots that
// production code wires through NewApp. Tests in this package
// build cobra commands directly and bypass the NewApp call path,
// so we replicate the wiring here.
func TestMain(m *testing.M) {
	lib, err := pack.NewLibrary()
	if err != nil {
		panic("failed to load library: " + err.Error())
	}
	capabilities.Configure(lib)
	m.Run()
}
