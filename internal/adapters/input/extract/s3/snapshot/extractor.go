package snapshot

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// SnapshotExtractor extracts S3 observations from AWS CLI JSON snapshot bundles.
// This is the healthcare-friendly input method that does not require IaC.
type SnapshotExtractor struct {
	ScopeMatcher ScopeMatcher
}

// ScopeMatcher selects whether a bucket is in scope for extraction.
type ScopeMatcher interface {
	IsHealthBucket(tags map[string]string, bucketName string) bool
}

// NewExtractor creates a new snapshot-based S3 extractor.
func NewExtractor(scopeMatcher ScopeMatcher) *SnapshotExtractor {
	return &SnapshotExtractor{ScopeMatcher: scopeMatcher}
}

// NewSnapshotExtractor keeps the historical constructor name.
func NewSnapshotExtractor(scopeMatcher ScopeMatcher) *SnapshotExtractor {
	return NewExtractor(scopeMatcher)
}

// ExtractFromSnapshotWithTime extracts with a specific timestamp for deterministic output.
func (e *SnapshotExtractor) ExtractFromSnapshotWithTime(ctx context.Context, snapshotDir string, now time.Time) ([]asset.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	listResp, err := e.loadBucketList(snapshotDir)
	if err != nil {
		return nil, err
	}
	if len(listResp.Buckets) == 0 {
		return nil, nil
	}

	var resources []asset.Asset
	for _, bucket := range listResp.Buckets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := kernel.NewBucketRef(bucket.Name).Validate(); err != nil {
			return nil, fmt.Errorf("snapshot contains %w", err)
		}

		obs := e.extractBucketObservation(snapshotDir, bucket.Name)
		if e.ScopeMatcher != nil && !e.ScopeMatcher.IsHealthBucket(obs.Tags, obs.BucketName) {
			continue
		}

		a := e.observationToAsset(obs)
		resources = append(resources, a)
	}

	sort.Slice(resources, func(i, j int) bool {
		return resources[i].ID < resources[j].ID
	})

	if len(resources) == 0 {
		return nil, nil
	}

	return e.wrapSnapshots(resources, now), nil
}

func (e *SnapshotExtractor) loadBucketList(snapshotDir string) (*ListBucketsResponse, error) {
	listBucketsPath := filepath.Join(snapshotDir, "list-buckets.json")
	listData, err := fsutil.ReadFileLimited(listBucketsPath)
	if err != nil {
		return nil, fmt.Errorf("read list-buckets.json (required): %w", err)
	}

	var listResp ListBucketsResponse
	if err := json.Unmarshal(listData, &listResp); err != nil {
		return nil, fmt.Errorf("parse list-buckets.json: %w", err)
	}
	return &listResp, nil
}

func (e *SnapshotExtractor) wrapSnapshots(resources []asset.Asset, now time.Time) []asset.Snapshot {
	pastTime := now.Add(-1 * time.Hour)

	snapshot1 := asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		GeneratedBy: &asset.GeneratedBy{
			SourceType: "aws-s3-snapshot",
			Tool:       "stave-s3-extractor",
		},
		CapturedAt: pastTime,
		Assets:     resources,
	}
	snapshot2 := asset.Snapshot{
		SchemaVersion: kernel.SchemaObservation,
		GeneratedBy: &asset.GeneratedBy{
			SourceType: "aws-s3-snapshot",
			Tool:       "stave-s3-extractor",
		},
		CapturedAt: now,
		Assets:     resources,
	}
	return []asset.Snapshot{snapshot1, snapshot2}
}

func (e *SnapshotExtractor) extractBucketObservation(snapshotDir, bucketName string) S3Observation {
	obs := S3Observation{
		BucketName: bucketName,
		BucketARN:  kernel.NewBucketRef(bucketName).ARN(),
		Tags:       make(map[string]string),
		Evidence:   []string{},
	}

	for _, spec := range s3Manifest {
		relativePath, data, ok := e.loadFile(snapshotDir, spec.api, bucketName)
		if !ok {
			obs.MissingInputs = append(obs.MissingInputs, relativePath)
			continue
		}
		if err := spec.apply(&obs, data); err != nil {
			// Preserve existing behavior: malformed JSON is ignored and not treated as missing.
			continue
		}
		obs.Evidence = append(obs.Evidence, fmt.Sprintf("%s from %s", spec.label, relativePath))
	}

	return obs
}

func (e *SnapshotExtractor) loadFile(snapshotDir, api, bucketName string) (relativePath string, data []byte, ok bool) {
	relPath := filepath.Join(api, bucketName+".json")
	fullPath := filepath.Join(snapshotDir, relPath)
	fileData, err := fsutil.ReadFileLimited(fullPath)
	if err != nil {
		return relPath, nil, false
	}
	return relPath, fileData, true
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
