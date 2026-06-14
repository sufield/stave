package capabilities_test

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/capabilities"
)

// TestMain registers the embedded policy library before any
// capabilities test runs. Production code routes through
// cmd.NewApp, which calls capabilities.Configure on startup;
// tests construct the package directly and bypass that wiring.
func TestMain(m *testing.M) {
	lib, err := pack.NewLibrary()
	if err != nil {
		panic("failed to load library: " + err.Error())
	}
	capabilities.Configure(lib)
	m.Run()
}
