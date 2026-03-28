package enginetest

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"

	"github.com/sufield/stave/internal/core/asset"
)

func ctl(id string) kernel.ControlID { return kernel.ControlID(id) }
func res(id string) asset.ID {
	return asset.ID(id)
}
func exp(t *testing.T, s string) policy.ExpiryDate {
	t.Helper()
	d, err := policy.ParseExpiryDate(s)
	if err != nil {
		t.Fatalf("policy.ParseExpiryDate(%q): %v", s, err)
	}
	return d
}

func TestExceptionConfig_NilConfig(t *testing.T) {
	var cfg *policy.ExceptionConfig
	rule := cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::mybucket"), time.Now())
	if rule != nil {
		t.Error("nil config should not suppress")
	}
}

func TestExceptionConfig_ExactMatch(t *testing.T) {
	cfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: ctl("CTL.S3.PUBLIC.001"),
			AssetID:   res("arn:aws:s3:::marketing-assets"),
			Reason:    "Intentionally public",
			Expires:   exp(t, "2099-12-31"),
		},
	})

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	rule := cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::marketing-assets"), now)
	if rule == nil {
		t.Error("exact match should suppress")
	}
	if rule == nil || rule.Reason != "Intentionally public" {
		t.Error("should return matching rule with reason")
	}
}

func TestExceptionConfig_GlobMatch(t *testing.T) {
	cfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: ctl("CTL.S3.PUBLIC.001"),
			AssetID:   res("arn:aws:s3:::staging-*"),
			Reason:    "Staging buckets exempt",
		},
	})

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	rule := cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::staging-logs"), now)
	if rule == nil {
		t.Error("glob pattern should match staging-logs")
	}

	rule = cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::production-logs"), now)
	if rule != nil {
		t.Error("glob pattern should not match production-logs")
	}
}

func TestExceptionConfig_ExpiredRule(t *testing.T) {
	cfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: ctl("CTL.S3.PUBLIC.001"),
			AssetID:   res("arn:aws:s3:::mybucket"),
			Reason:    "Temporary exemption",
			Expires:   exp(t, "2026-01-01"),
		},
	})

	// After expiry
	afterExpiry := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	rule := cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::mybucket"), afterExpiry)
	if rule != nil {
		t.Error("expired rule should not suppress")
	}

	// Before expiry
	beforeExpiry := time.Date(2025, 12, 15, 0, 0, 0, 0, time.UTC)
	rule = cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::mybucket"), beforeExpiry)
	if rule == nil {
		t.Error("non-expired rule should suppress")
	}
}

func TestExceptionConfig_NoMatch(t *testing.T) {
	cfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: ctl("CTL.S3.PUBLIC.001"),
			AssetID:   res("arn:aws:s3:::marketing-assets"),
			Reason:    "Intentionally public",
		},
	})

	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	// Different control
	rule := cfg.ShouldExcept(ctl("CTL.S3.ENCRYPT.001"), res("arn:aws:s3:::marketing-assets"), now)
	if rule != nil {
		t.Error("different control_id should not match")
	}

	// Different asset
	rule = cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::other-bucket"), now)
	if rule != nil {
		t.Error("different asset_id should not match")
	}
}

func TestExceptionConfig_NoExpiry(t *testing.T) {
	cfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: ctl("CTL.S3.PUBLIC.001"),
			AssetID:   res("arn:aws:s3:::mybucket"),
			Reason:    "Permanent exception",
		},
	})

	farFuture := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	rule := cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::mybucket"), farFuture)
	if rule == nil {
		t.Error("rule without expiry should always match")
	}
}

func TestExceptionConfig_ExpiryOnExactDate(t *testing.T) {
	cfg := policy.NewExceptionConfig([]policy.ExceptionRule{
		{
			ControlID: ctl("CTL.S3.PUBLIC.001"),
			AssetID:   res("arn:aws:s3:::mybucket"),
			Reason:    "Temporary",
			Expires:   exp(t, "2026-06-01"),
		},
	})

	// During the expiry date, the rule should still be active (end-of-day inclusive).
	duringExpiry := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	rule := cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::mybucket"), duringExpiry)
	if rule == nil {
		t.Error("rule should still suppress during the expiry date")
	}

	// At the start of the next day, the rule should be expired.
	nextDay := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC)
	rule = cfg.ShouldExcept(ctl("CTL.S3.PUBLIC.001"), res("arn:aws:s3:::mybucket"), nextDay)
	if rule != nil {
		t.Error("rule should be expired at the start of the next day")
	}
}

func TestParseExpiryDate_Invalid(t *testing.T) {
	if _, err := policy.ParseExpiryDate("2026-13-01"); err == nil {
		t.Fatal("expected invalid exception expiry to fail parsing")
	}
}
