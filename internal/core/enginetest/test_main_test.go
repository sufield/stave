package enginetest

import (
	"os"
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws"
)

// TestMain runs domain-layer tests. Registers the AWS provider so
// TestNoCredentialEnvReads can scan source files against the
// AWS-banned env-var list (kernel ships its banned-credential-keys
// registry empty; aws.Register seeds the AWS_* entries).
func TestMain(m *testing.M) {
	aws.Register()
	os.Exit(m.Run())
}
