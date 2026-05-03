package evaluate

import (
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws"
	// Blank import: AWS controls' init() must run so the hipaa
	// profile has controls in the global registry. cmd.NewApp does
	// this in production via its own blank import; tests construct
	// the cobra subcommand directly and bypass that wiring.
	_ "github.com/sufield/stave/internal/platform/providers/aws/compliance"
)

// TestMain registers the AWS provider before any evaluate-cmd test
// runs. Production code routes through cmd.NewApp, which calls
// aws.Register on startup; tests construct the cobra subcommand
// directly and bypass that wiring.
func TestMain(m *testing.M) {
	aws.Register()
	m.Run()
}
