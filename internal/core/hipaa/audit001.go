package hipaa

import (
	"fmt"

	"github.com/sufield/stave/internal/core/asset"
)

// audit001 checks that server access logging is enabled with a target bucket.
type audit001 struct {
	Definition
}

func init() {
	AuditRegistry.MustRegister(&audit001{
		Definition: Build(
			WithID("AUDIT.001"),
			WithDescription("Server access logging must be enabled with a configured target bucket"),
			WithSeverity(Critical),
			WithComplianceProfiles("hipaa", "pci-dss", "cis-s3"),
			WithComplianceRef("hipaa", "§164.312(b)"),
		),
	})
}

// Evaluate checks that logging.target_bucket is set for every S3 bucket.
func (inv *audit001) Evaluate(snap asset.Snapshot) Result {
	for _, a := range snap.Assets {
		if !isS3Bucket(a) {
			continue
		}

		logging := loggingMap(a)
		target := toString(logging["target_bucket"])
		if target == "" {
			return inv.FailResult(
				fmt.Sprintf("Bucket %s: server access logging is not enabled. Logs cannot be obtained retroactively from AWS — if a security incident occurs without logging enabled, no forensic evidence exists", a.ID),
				"Enable server access logging on the bucket. Set a target bucket in a separate account or with write-only permissions to prevent log tampering.",
			)
		}
	}

	return inv.PassResult()
}

func loggingMap(a asset.Asset) map[string]any {
	s := storageMap(a)
	if s == nil {
		return nil
	}
	l, _ := s["logging"].(map[string]any)
	return l
}
