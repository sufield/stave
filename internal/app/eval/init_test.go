package eval_test

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/capabilities"
)

// TestMain registers the embedded policy library before any
// eval test runs. Tests in this package exercise control-pack
// loading, which pulls the lazy capabilities.Manifest. Production
// wires this in cmd.NewApp; tests construct the package directly.
func TestMain(m *testing.M) {
	capabilities.Configure(pack.MustNewLibrary())
	m.Run()
}
