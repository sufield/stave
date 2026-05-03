package policy

import (
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws"
)

// TestMain registers the AWS provider before tests in this package
// run. MinimumS3IngestIAMActions reads from the kernel's per-vendor
// permission registry (now empty by default) — without this call
// the function returns an empty list and the manifest tests fail.
func TestMain(m *testing.M) {
	aws.Register()
	m.Run()
}
