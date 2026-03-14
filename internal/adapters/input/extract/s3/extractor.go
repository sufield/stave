// Package s3 extracts S3 bucket observations from Terraform plan JSON.
package s3

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"sort"
	"time"

	"github.com/samber/lo"
	s3acl "github.com/sufield/stave/internal/adapters/input/extract/s3/acl"
	s3resource "github.com/sufield/stave/internal/adapters/input/extract/s3/resource"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	s3terraform "github.com/sufield/stave/internal/adapters/input/extract/s3/terraform"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// Extractor extracts S3 observations from Terraform plan JSON.
type Extractor struct {
	ScopeConfig *ScopeConfig
	SnapshotGap time.Duration
}

// NewExtractor creates a new S3 extractor.
func NewExtractor(scopeConfig *ScopeConfig) *Extractor {
	return &Extractor{ScopeConfig: scopeConfig}
}

// ExtractFromFile extracts S3 observations from a Terraform plan JSON file.
func (e *Extractor) ExtractFromFile(ctx context.Context, path string) ([]asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read plan file: %w", err)
	}
	return e.Extract(ctx, data)
}

// Extract parses Terraform plan JSON and returns S3 bucket observations.
// It generates two snapshots: one backdated (to establish duration) and one current.
func (e *Extractor) Extract(ctx context.Context, data []byte) ([]asset.Snapshot, error) {
	return e.ExtractWithTime(ctx, data, time.Now().UTC())
}

// ExtractWithTime parses Terraform plan JSON with a specific "now" time.
// It generates two snapshots: one 1 hour before "now" and one at "now".
// This allows the evaluator to detect violations with max_unsafe_duration=0h.
func (e *Extractor) ExtractWithTime(ctx context.Context, data []byte, now time.Time) ([]asset.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var plan s3terraform.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parse terraform plan: %w", err)
	}

	// Collect all S3-related assets in a single mutable state container.
	state := s3terraform.NewState()
	if err := e.collectFromRootModule(ctx, plan.PlannedValues.RootModule.Resources, state); err != nil {
		return nil, err
	}
	if err := e.collectFromResourceChanges(ctx, plan.ResourceChanges, state); err != nil {
		return nil, err
	}

	// Account PAB is passed to bucketToResource for effective per-flag merging.
	state.HydrateBuckets()

	resources := e.buildResourceSlices(state)

	if len(resources) == 0 {
		return nil, nil
	}

	return e.wrapSnapshots(resources, now), nil
}

func (e *Extractor) collectFromRootModule(
	ctx context.Context,
	resources []s3terraform.Resource,
	state *s3terraform.State,
) error {
	for _, res := range resources {
		if err := ctx.Err(); err != nil {
			return err
		}
		s3terraform.CollectResource(res.Type, res.Name, res.Values, state)
	}
	return nil
}

func (e *Extractor) collectFromResourceChanges(
	ctx context.Context,
	changes []s3terraform.ResourceChange,
	state *s3terraform.State,
) error {
	for _, rc := range changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if rc.Change.After != nil {
			s3terraform.CollectResource(rc.Type, rc.Name, rc.Change.After, state)
		}
	}
	return nil
}

func (e *Extractor) buildResourceSlices(state *s3terraform.State) []asset.Asset {
	bucketNames := lo.Keys(state.Buckets)
	sort.Strings(bucketNames)

	resources := make([]asset.Asset, 0, len(bucketNames))
	for _, name := range bucketNames {
		bucket := fromTerraformBucket(state.Buckets[name])
		if e.ScopeConfig != nil && !e.ScopeConfig.IsHealthBucket(bucket.Tags, bucket.Name.Name()) {
			continue
		}
		resources = append(resources, s3resource.BuildBucketAsset(bucket, state.AccountPAB))
	}
	return resources
}

func fromTerraformBucket(bucket *s3terraform.Bucket) *s3storage.S3Bucket {
	if bucket == nil {
		return nil
	}
	converted := &s3storage.S3Bucket{
		Name:              kernel.NewBucketRef(bucket.Name),
		ARN:               bucket.ARN,
		Tags:              cloneStringMap(bucket.Tags),
		PolicyJSON:        bucket.PolicyJSON,
		ACLGrants:         make([]s3acl.Grant, 0, len(bucket.ACLGrants)),
		PublicAccessBlock: bucket.PublicAccessBlock,
		Encryption:        bucket.Encryption,
		Versioning:        bucket.Versioning,
		Logging:           bucket.Logging,
		Lifecycle:         bucket.Lifecycle,
		ObjectLock:        bucket.ObjectLock,
		Website:           bucket.Website,
	}
	for _, grant := range bucket.ACLGrants {
		converted.ACLGrants = append(converted.ACLGrants, s3acl.Grant{
			Grantee:    grant.Grantee,
			Permission: grant.Permission,
		})
	}
	return converted
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	maps.Copy(out, input)
	return out
}

func (e *Extractor) wrapSnapshots(resources []asset.Asset, now time.Time) []asset.Snapshot {
	gap := e.SnapshotGap
	if gap <= 0 {
		gap = time.Hour
	}
	pastTime := now.Add(-gap)

	snapshot1 := asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		GeneratedBy: &asset.GeneratedBy{
			SourceType: kernel.SourceTypeTerraformPlanJSON,
			Tool:       "stave-s3-extractor",
		},
		CapturedAt: pastTime,
		Assets:     resources,
	}

	snapshot2 := asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		GeneratedBy: &asset.GeneratedBy{
			SourceType: kernel.SourceTypeTerraformPlanJSON,
			Tool:       "stave-s3-extractor",
		},
		CapturedAt: now,
		Assets:     resources,
	}

	return []asset.Snapshot{snapshot1, snapshot2}
}
