package collectorcontract

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestLoad(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(c.Entries) == 0 {
		t.Fatal("expected non-empty contract entries")
	}
	if c.Version != "1.0" {
		t.Errorf("expected version 1.0, got %q", c.Version)
	}
}

func TestFieldIndex(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	idx := c.FieldIndex()
	if _, ok := idx["denies_assume_root"]; !ok {
		t.Error("expected denies_assume_root in index")
	}
}

func TestValidateSnapshots_PassBoolean(t *testing.T) {
	c := &Contract{
		Entries: []Entry{{Field: "has_public_ip", Type: "boolean"}},
	}
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{{
			ID:   "i-123",
			Type: kernel.AssetType("aws_ec2_instance"),
			Properties: map[string]any{
				"has_public_ip": true,
			},
		}},
	}}
	r := ValidateSnapshots(snaps, c)
	if r.Pass != 1 {
		t.Errorf("expected 1 pass, got %d", r.Pass)
	}
	if r.HasViolations() {
		t.Error("expected no violations")
	}
}

func TestValidateSnapshots_WrongType(t *testing.T) {
	c := &Contract{
		Entries: []Entry{{Field: "has_public_ip", Type: "boolean"}},
	}
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{{
			ID:   "i-123",
			Type: kernel.AssetType("aws_ec2_instance"),
			Properties: map[string]any{
				"has_public_ip": "true",
			},
		}},
	}}
	r := ValidateSnapshots(snaps, c)
	if r.WrongType != 1 {
		t.Errorf("expected 1 wrong type, got %d", r.WrongType)
	}
	if !r.HasViolations() {
		t.Error("expected violations")
	}
}

func TestValidateSnapshots_NullField(t *testing.T) {
	c := &Contract{
		Entries: []Entry{{
			Field:     "has_public_ip",
			Type:      "boolean",
			Consumers: []string{"CTL.EC2.PUBLIC.001"},
		}},
	}
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{{
			ID:   "i-123",
			Type: kernel.AssetType("aws_ec2_instance"),
			Properties: map[string]any{
				"has_public_ip": nil,
			},
		}},
	}}
	r := ValidateSnapshots(snaps, c)
	if r.Null != 1 {
		t.Errorf("expected 1 null, got %d", r.Null)
	}
	if !r.HasWarnings() {
		t.Error("expected warnings")
	}
	if r.HasViolations() {
		t.Error("null should be a warning, not a violation")
	}
}

func TestValidateSnapshots_MissingApplicable(t *testing.T) {
	c := &Contract{
		Entries: []Entry{{Field: "has_public_ip", Type: "boolean"}},
	}
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{{
			ID:         "i-123",
			Type:       kernel.AssetType("aws_ec2_instance"),
			Properties: map[string]any{},
		}},
	}}
	r := ValidateSnapshots(snaps, c)
	if r.Missing != 1 {
		t.Errorf("expected 1 missing, got %d", r.Missing)
	}
}

func TestValidateSnapshots_MissingNotApplicable(t *testing.T) {
	c := &Contract{
		Entries: []Entry{{Field: "has_public_ip", Type: "boolean"}},
	}
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{{
			ID:         "bucket-1",
			Type:       kernel.AssetType("aws_s3_bucket"),
			Properties: map[string]any{},
		}},
	}}
	r := ValidateSnapshots(snaps, c)
	if r.Missing != 0 {
		t.Errorf("has_public_ip should not apply to s3_bucket, got %d missing", r.Missing)
	}
	if r.Pass != 1 {
		t.Errorf("expected 1 pass (not applicable = pass), got %d", r.Pass)
	}
}

func TestValidateSnapshots_NumberInsteadOfBool(t *testing.T) {
	c := &Contract{
		Entries: []Entry{{Field: "is_encrypted", Type: "boolean"}},
	}
	snaps := []asset.Snapshot{{
		Assets: []asset.Asset{{
			ID:   "vol-1",
			Type: kernel.AssetType("aws_ebs_volume"),
			Properties: map[string]any{
				"is_encrypted": float64(1),
			},
		}},
	}}
	r := ValidateSnapshots(snaps, c)
	if r.WrongType != 1 {
		t.Errorf("expected 1 wrong type for number-as-bool, got %d", r.WrongType)
	}
}

func TestCheckBoolean(t *testing.T) {
	tests := []struct {
		val    any
		status Status
	}{
		{true, StatusPass},
		{false, StatusPass},
		{"true", StatusWrongType},
		{"false", StatusWrongType},
		{float64(1), StatusWrongType},
		{float64(0), StatusWrongType},
		{42, StatusWrongType},
	}
	for _, tt := range tests {
		s, _ := checkBoolean(tt.val)
		if s != tt.status {
			t.Errorf("checkBoolean(%v): got %d, want %d", tt.val, s, tt.status)
		}
	}
}
