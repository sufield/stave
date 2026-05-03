package compliance_test

import (
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws"
	// Blank import: each control's init() registers into the global
	// compliance.ControlCatalog. providers/aws no longer transitively
	// imports compliance (see cmd/root.go for the production wiring),
	// so tests that depend on AWS controls being registered must
	// pull the package in directly.
	_ "github.com/sufield/stave/internal/platform/providers/aws/compliance"
)

// TestMain registers the AWS provider before any compliance test
// runs. Tests that exercise the registry (ByProfile, NewTestCatalog
// parity, hipaa profile presence) need AWS S3 controls registered
// in the global ControlCatalog. Living in an external _test package
// avoids a production-time import cycle (providers/aws/compliance
// imports core/compliance for Definition).
func TestMain(m *testing.M) {
	aws.Register()
	m.Run()
}
