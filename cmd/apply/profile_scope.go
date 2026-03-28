package apply

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/asset"
)

func resolveScopeFilter(cfg Config) *asset.ScopeFilter {
	if cfg.IncludeAll {
		return asset.UniversalFilter
	}
	if len(cfg.BucketAllowlist) > 0 {
		return asset.NewScopeFilterFromAllowlist(cfg.BucketAllowlist)
	}
	return asset.DefaultHealthcareScopeFilter()
}

func filterSnapshots(stderr io.Writer, quiet bool, cfg Config, snapshots []asset.Snapshot) []asset.Snapshot {
	if len(snapshots) == 0 {
		if !quiet {
			fmt.Fprintln(stderr, "No snapshots in observations file")
		}
		return nil
	}

	scopeFilter := resolveScopeFilter(cfg)
	filtered := asset.FilterSnapshots(scopeFilter, snapshots)
	if len(filtered) == 0 {
		if !quiet {
			fmt.Fprintln(stderr, "No S3 buckets matching configured scope found in observations")
		}
		return nil
	}

	return filtered
}
