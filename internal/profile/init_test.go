package profile_test

import (
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws"
	// Blank import: AWS controls' init() must run for the hipaa
	// profile to have controls in the global registry. providers/aws
	// is leaf-imported so providers/aws/compliance can import it; we
	// pull compliance in explicitly here.
	_ "github.com/sufield/stave/internal/platform/providers/aws/compliance"
)

// TestMain registers the AWS provider before any profile test runs.
// Profile-level tests evaluate the "hipaa" profile against the
// global compliance registry, so AWS S3 controls must be registered.
// External _test package keeps AWS-specific code out of the
// production profile package's import graph.
func TestMain(m *testing.M) {
	aws.Register()
	m.Run()
}
