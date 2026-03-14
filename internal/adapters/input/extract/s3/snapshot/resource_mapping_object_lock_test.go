package snapshot

import (
	"testing"

	s3resource "github.com/sufield/stave/internal/adapters/input/extract/s3/resource"
	s3storage "github.com/sufield/stave/internal/adapters/input/extract/s3/storage"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestNewObjectLockEvidence(t *testing.T) {
	tests := []struct {
		name string
		in   *s3storage.ObjectLockConfig
		want *s3storage.ObjectLockEvidence
	}{
		{
			name: "nil config returns nil",
			in:   nil,
			want: nil,
		},
		{
			name: "disabled returns nil",
			in: &s3storage.ObjectLockConfig{
				Enabled: false,
				Mode:    s3storage.ObjectLockCompliance,
			},
			want: nil,
		},
		{
			name: "enabled with full values",
			in: &s3storage.ObjectLockConfig{
				Enabled:       true,
				Mode:          s3storage.ObjectLockCompliance,
				RetentionDays: 30,
			},
			want: &s3storage.ObjectLockEvidence{
				Enabled:       true,
				Mode:          "COMPLIANCE",
				RetentionDays: 30,
			},
		},
		{
			name: "enabled with zero values keeps enabled only",
			in: &s3storage.ObjectLockConfig{
				Enabled: true,
			},
			want: &s3storage.ObjectLockEvidence{
				Enabled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s3storage.NewObjectLockEvidence(tt.in)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil object lock evidence")
			}
			if got.Enabled != tt.want.Enabled || got.Mode != tt.want.Mode || got.RetentionDays != tt.want.RetentionDays {
				t.Fatalf("unexpected object lock evidence: got=%+v want=%+v", *got, *tt.want)
			}
		})
	}
}

func TestBuildAWSS3Evidence_OmitsObjectLockWhenNotEnabled(t *testing.T) {
	bucket := &s3storage.S3Bucket{
		Name: kernel.NewBucketRef("no-lock"),
	}

	out := s3resource.ToMap(s3storage.BuildAWSS3Evidence(bucket, s3storage.S3AnalysisResult{}))
	security, ok := out["security"].(map[string]any)
	if !ok {
		t.Fatal("expected security evidence map")
	}
	if _, ok := security["object_lock"]; ok {
		t.Fatal("expected object_lock to be omitted when object lock is not enabled")
	}
}

func TestBuildAWSS3Evidence_ObjectLockUsesOmitempty(t *testing.T) {
	bucket := &s3storage.S3Bucket{
		Name: kernel.NewBucketRef("with-lock"),
		ObjectLock: &s3storage.ObjectLockConfig{
			Enabled: true,
		},
	}

	out := s3resource.ToMap(s3storage.BuildAWSS3Evidence(bucket, s3storage.S3AnalysisResult{}))
	security, ok := out["security"].(map[string]any)
	if !ok {
		t.Fatal("expected security evidence map")
	}
	raw, ok := security["object_lock"].(map[string]any)
	if !ok {
		t.Fatal("expected object_lock evidence map")
	}
	if enabled, _ := raw["enabled"].(bool); !enabled {
		t.Fatal("expected object_lock.enabled=true")
	}
	if _, ok := raw["mode"]; ok {
		t.Fatal("expected object_lock.mode omitted for empty mode")
	}
	if _, ok := raw["retention_days"]; ok {
		t.Fatal("expected object_lock.retention_days omitted for zero retention")
	}
}
