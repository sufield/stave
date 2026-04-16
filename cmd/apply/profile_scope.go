package apply

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/asset"
)

func resolveScopeFilter(cfg Config) *asset.AuditScope {
	if cfg.IncludeAll {
		return asset.GlobalScope
	}
	if len(cfg.BucketAllowlist) > 0 {
		return asset.NewAuditScopeFromAllowlist(cfg.BucketAllowlist)
	}
	// Domain-scoped profiles (non-S3) already scope by control directory;
	// applying the PHI tag filter would exclude all assets that lack
	// DataDomain=health tags. Use GlobalScope for these profiles.
	if profileControlDomain(cfg.Profile) != "" && cfg.Profile != ProfileAWSS3 {
		return asset.GlobalScope
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
