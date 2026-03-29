package risk

import (
	"testing"
	"time"
)

func TestNormalizeActions(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"basic", []string{"S3:GetObject", "S3:PutObject"}, []string{"s3:getobject", "s3:putobject"}},
		{"whitespace", []string{"  S3:GetObject  ", "\tS3:PutObject\n"}, []string{"s3:getobject", "s3:putobject"}},
		{"empty", nil, []string{}},
		{"already lowercase", []string{"s3:getobject"}, []string{"s3:getobject"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeActions(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestValidateStatuses(t *testing.T) {
	t.Run("valid statuses", func(t *testing.T) {
		got, err := ValidateStatuses([]string{"overdue", "DUE_NOW", " upcoming "})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []ThresholdStatus{StatusOverdue, StatusDueNow, StatusUpcoming}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("index %d = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("empty strings skipped", func(t *testing.T) {
		got, err := ValidateStatuses([]string{"", "  ", "OVERDUE"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("len = %d, want 1", len(got))
		}
		if got[0] != StatusOverdue {
			t.Errorf("got %q, want OVERDUE", got[0])
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		_, err := ValidateStatuses([]string{"INVALID"})
		if err == nil {
			t.Fatal("expected error for invalid status")
		}
	})

	t.Run("empty input", func(t *testing.T) {
		got, err := ValidateStatuses(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("len = %d, want 0", len(got))
		}
	})
}

func TestThresholdItems_CountOverdue(t *testing.T) {
	items := ThresholdItems{
		{Status: StatusOverdue},
		{Status: StatusDueNow},
		{Status: StatusOverdue},
		{Status: StatusUpcoming},
	}
	if got := items.CountOverdue(); got != 2 {
		t.Errorf("CountOverdue() = %d, want 2", got)
	}

	empty := ThresholdItems{}
	if got := empty.CountOverdue(); got != 0 {
		t.Errorf("empty CountOverdue() = %d, want 0", got)
	}
}

func TestThresholdItems_HasAnyRisk(t *testing.T) {
	if (ThresholdItems{}).HasAnyRisk() {
		t.Error("empty should not have risk")
	}
	if !(ThresholdItems{{Status: StatusUpcoming}}).HasAnyRisk() {
		t.Error("non-empty should have risk")
	}
}

func TestThresholdItems_Summarize(t *testing.T) {
	dueSoonThreshold := 2 * time.Hour
	items := ThresholdItems{
		{Status: StatusOverdue, Remaining: -1 * time.Hour},
		{Status: StatusDueNow, Remaining: 0},
		{Status: StatusUpcoming, Remaining: 1 * time.Hour},  // due soon (within 2h)
		{Status: StatusUpcoming, Remaining: 5 * time.Hour},  // later (beyond 2h)
		{Status: StatusUpcoming, Remaining: -1 * time.Hour}, // remaining <=0 counts as later
	}

	s := items.Summarize(dueSoonThreshold)
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
	if s.Overdue != 1 {
		t.Errorf("Overdue = %d, want 1", s.Overdue)
	}
	if s.DueNow != 1 {
		t.Errorf("DueNow = %d, want 1", s.DueNow)
	}
	if s.DueSoon != 1 {
		t.Errorf("DueSoon = %d, want 1", s.DueSoon)
	}
	if s.Later != 2 {
		t.Errorf("Later = %d, want 2", s.Later)
	}
}

func TestThresholdItems_Summarize_Empty(t *testing.T) {
	s := ThresholdItems{}.Summarize(2 * time.Hour)
	if s.Total != 0 || s.Overdue != 0 || s.DueNow != 0 || s.DueSoon != 0 || s.Later != 0 {
		t.Errorf("empty summary should be all zeros, got %+v", s)
	}
}
