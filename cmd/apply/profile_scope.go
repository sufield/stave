package apply

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/asset"
)

func resolveScopeFilter(cfg Config) *asset.AuditScope {
	if cfg.IncludeAll {
		return asset.GetGlobalScope()
	}
	if len(cfg.BucketAllowlist) > 0 {
		return asset.NewAuditScopeFromAllowlist(cfg.BucketAllowlist)
	}
	// Only the AWS-S3 profile keeps the PHI default scope. Every other
	// profile — domain-scoped (IAM/EFS/GCS) AND cross-domain
	// (HIPAA/SOC2/CIS/PCI/NIST/FedRAMP/GDPR/FFIEC/ISO/NISTCSF) —
	// gets GetGlobalScope(), because PHIBoundary filters out IAM, VPC,
	// KMS, compute, and other non-storage assets those profiles
	// must evaluate. Cross-domain profiles previously fell through
	// to PHIBoundary because profileControlDomain returns "" for
	// them; the result was a silent zero-findings outcome that
	// looked like compliance evidence. Match the original intent
	// (only the S3 default-scope use case keeps PHI filtering).
	if cfg.Profile != ProfileAWSS3 {
		return asset.GetGlobalScope()
	}
	return asset.PHIBoundary()
}

func filterSnapshots(stderr io.Writer, quiet bool, cfg Config, snapshots []asset.Snapshot) []asset.Snapshot {
	if len(snapshots) == 0 {
		if !quiet {
			fmt.Fprintln(stderr, "No snapshots in observations file")
		}
		return nil
	}

	scopeFilter := resolveScopeFilter(cfg)
	filtered := asset.ApplyScopeToSnapshots(scopeFilter, snapshots)
	if len(filtered) == 0 {
		if !quiet {
			fmt.Fprintln(stderr, "No S3 buckets matching configured scope found in observations")
		}
		return nil
	}

	return filtered
}
