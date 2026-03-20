package apply

import (
	"fmt"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

func (r *Runner) resolveScopeFilter(cfg Config) asset.AssetPredicate {
	if cfg.IncludeAll {
		return asset.UniversalFilter
	}
	if len(cfg.BucketAllowlist) > 0 {
		return asset.NewScopeFilterFromAllowlist(cfg.BucketAllowlist)
	}
	return asset.DefaultHealthcareScopeFilter()
}

func (r *Runner) filterSnapshots(cfg Config, snapshots []asset.Snapshot) []asset.Snapshot {
	if len(snapshots) == 0 {
		if !cfg.Quiet {
			fmt.Fprintln(cfg.Stderr, "No snapshots in observations file")
		}
		return nil
	}

	scopeFilter := r.resolveScopeFilter(cfg)
	filtered := asset.FilterSnapshots(scopeFilter, snapshots)
	if len(filtered) == 0 {
		if !cfg.Quiet {
			fmt.Fprintln(cfg.Stderr, "No S3 buckets matching health scope found in observations")
		}
		return nil
	}

	return filtered
}
