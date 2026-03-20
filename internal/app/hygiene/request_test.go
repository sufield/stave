package hygiene

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

func TestRequestParse(t *testing.T) {
	t.Run("parses complete request", func(t *testing.T) {
		req := Request{
			MaxUnsafe: "7d",
			DueSoon:   "24h",
			Lookback:  "7d",
			DueWithin: "48h",
			KeepMin:   2,
			NowTime:   "2026-01-20T12:30:00+05:00",
			Statuses:  []risk.Status{risk.StatusOverdue, risk.StatusDueNow, risk.StatusUpcoming},
		}

		parsed, err := req.Parse()
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if parsed.MaxUnsafe != 168*time.Hour {
			t.Fatalf("MaxUnsafe = %s, want %s", parsed.MaxUnsafe, 168*time.Hour)
		}
		if parsed.DueSoon != 24*time.Hour {
			t.Fatalf("DueSoon = %s, want %s", parsed.DueSoon, 24*time.Hour)
		}
		if parsed.Lookback != 168*time.Hour {
			t.Fatalf("Lookback = %s, want %s", parsed.Lookback, 168*time.Hour)
		}
		if parsed.DueWithin == nil || *parsed.DueWithin != 48*time.Hour {
			t.Fatalf("DueWithin = %v, want %s", parsed.DueWithin, 48*time.Hour)
		}
		wantNow := time.Date(2026, 1, 20, 7, 30, 0, 0, time.UTC)
		if !parsed.Now.Equal(wantNow) {
			t.Fatalf("Now = %s, want %s", parsed.Now.Format(time.RFC3339), wantNow.Format(time.RFC3339))
		}
	})

	t.Run("uses wall clock when now omitted", func(t *testing.T) {
		req := Request{
			MaxUnsafe: "7d",
			DueSoon:   "24h",
			Lookback:  "7d",
			KeepMin:   0,
		}
		before := time.Now().UTC()
		parsed, err := req.Parse()
		after := time.Now().UTC()

		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		if parsed.DueWithin != nil {
			t.Fatalf("DueWithin = %v, want nil", parsed.DueWithin)
		}
		if parsed.Now.Before(before) || parsed.Now.After(after) {
			t.Fatalf("Now = %v, want between %v and %v", parsed.Now, before, after)
		}
	})
}

func TestRequestParseUsesNowFunc(t *testing.T) {
	fixed := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)
	req := Request{
		MaxUnsafe: "7d",
		DueSoon:   "24h",
		Lookback:  "7d",
		KeepMin:   0,
		NowFunc:   func() time.Time { return fixed },
	}
	parsed, err := req.Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !parsed.Now.Equal(fixed) {
		t.Fatalf("Now = %s, want %s", parsed.Now.Format(time.RFC3339), fixed.Format(time.RFC3339))
	}
}

func TestRequestParseErrors(t *testing.T) {
	t.Run("invalid keep-min", func(t *testing.T) {
		req := Request{
			MaxUnsafe: "7d",
			DueSoon:   "24h",
			Lookback:  "7d",
			KeepMin:   -1,
		}

		_, err := req.Parse()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid keep-min") {
			t.Fatalf("error = %q, want to contain %q", err.Error(), "invalid keep-min")
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		req := Request{
			MaxUnsafe: "7d",
			DueSoon:   "24h",
			Lookback:  "7d",
			KeepMin:   0,
			Statuses:  []risk.Status{"BOGUS"},
		}

		_, err := req.Parse()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid status") {
			t.Fatalf("error = %q, want to contain %q", err.Error(), "invalid status")
		}
	})

	t.Run("invalid now", func(t *testing.T) {
		req := Request{
			MaxUnsafe: "7d",
			DueSoon:   "24h",
			Lookback:  "7d",
			KeepMin:   0,
			NowTime:   "not-rfc3339",
		}

		_, err := req.Parse()
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "invalid timestamp") {
			t.Fatalf("error = %q, want to contain %q", err.Error(), "invalid timestamp")
		}
	})
}
