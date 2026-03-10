package json

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkLoadSnapshots measures the full observation loading pipeline:
// read file → hash → schema validate → unmarshal → normalize.
// Run with: go test -bench=BenchmarkLoadSnapshots -benchmem ./internal/adapters/input/observations/json/
func BenchmarkLoadSnapshots(b *testing.B) {
	dir := b.TempDir()
	snapshot := buildBenchmarkSnapshot(10)
	if err := os.WriteFile(filepath.Join(dir, "snap1.json"), snapshot, 0644); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snap2.json"), snapshot, 0644); err != nil {
		b.Fatal(err)
	}

	loader := NewObservationLoader()
	ctx := context.Background()

	b.ResetTimer()
	for b.Loop() {
		if _, err := loader.LoadSnapshots(ctx, dir); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkProcess measures the single-file processing pipeline (hash + validate + unmarshal).
func BenchmarkProcess(b *testing.B) {
	snapshot := buildBenchmarkSnapshot(50)
	loader := NewObservationLoader()

	b.ResetTimer()
	for b.Loop() {
		if _, _, err := loader.process(snapshot, "bench.json"); err != nil {
			b.Fatal(err)
		}
	}
}

func buildBenchmarkSnapshot(assetCount int) []byte {
	var assets strings.Builder
	for i := range assetCount {
		if i > 0 {
			assets.WriteString(",")
		}
		assets.WriteString(fmt.Sprintf(`{
			"id": "arn:aws:s3:::bucket-%d",
			"type": "aws_s3_bucket",
			"vendor": "aws",
			"properties": {
				"storage": {
					"visibility": {"public_read": false, "public_write": false},
					"encryption": {"at_rest_enabled": true, "algorithm": "AES256"},
					"versioning": {"enabled": true},
					"logging": {"enabled": true},
					"controls": {"public_access_fully_blocked": true}
				}
			}
		}`, i))
	}
	return fmt.Appendf(nil, `{
		"schema_version": "obs.v0.1",
		"generated_by": {"source_type": "aws-s3-snapshot", "tool": "benchmark"},
		"captured_at": "2026-01-15T00:00:00Z",
		"assets": [%s]
	}`, assets.String())
}
