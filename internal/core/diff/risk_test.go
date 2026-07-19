package diff

import "testing"

func TestClassifyRisk_ProtectiveFieldLost(t *testing.T) {
	// imdsv2_enforced true → false = risk increasing
	got := ClassifyRisk("imdsv2_enforced", true, false)
	if got != RiskIncreasing {
		t.Errorf("imdsv2_enforced true→false: got %v, want RiskIncreasing", got)
	}
}

func TestClassifyRisk_ProtectiveFieldGained(t *testing.T) {
	// is_encrypted false → true = risk decreasing
	got := ClassifyRisk("is_encrypted", false, true)
	if got != RiskDecreasing {
		t.Errorf("is_encrypted false→true: got %v, want RiskDecreasing", got)
	}
}

func TestClassifyRisk_ExposureFieldGained(t *testing.T) {
	// has_public_ip false → true = risk increasing
	got := ClassifyRisk("has_public_ip", false, true)
	if got != RiskIncreasing {
		t.Errorf("has_public_ip false→true: got %v, want RiskIncreasing", got)
	}
}

func TestClassifyRisk_ExposureFieldLost(t *testing.T) {
	// public_read true → false = risk decreasing
	got := ClassifyRisk("public_read", true, false)
	if got != RiskDecreasing {
		t.Errorf("public_read true→false: got %v, want RiskDecreasing", got)
	}
}

func TestClassifyRisk_DeniesPrefix(t *testing.T) {
	// denies_assume_root true → false = risk increasing (lost protection)
	got := ClassifyRisk("denies_assume_root", true, false)
	if got != RiskIncreasing {
		t.Errorf("denies_assume_root true→false: got %v, want RiskIncreasing", got)
	}

	// denies_assume_root false → true = risk decreasing (gained protection)
	got = ClassifyRisk("denies_assume_root", false, true)
	if got != RiskDecreasing {
		t.Errorf("denies_assume_root false→true: got %v, want RiskDecreasing", got)
	}
}

func TestClassifyRisk_NonBoolean(t *testing.T) {
	// string field → neutral
	got := ClassifyRisk("instance_type", "t3.micro", "t3.large")
	if got != RiskNeutral {
		t.Errorf("non-boolean: got %v, want RiskNeutral", got)
	}
}

func TestClassifyRisk_UnknownField(t *testing.T) {
	// unknown boolean field → neutral
	got := ClassifyRisk("some_random_field", true, false)
	if got != RiskNeutral {
		t.Errorf("unknown field: got %v, want RiskNeutral", got)
	}
}

func TestClassifyRisk_NilValues(t *testing.T) {
	// nil → true for unknown field → neutral
	got := ClassifyRisk("unknown", nil, true)
	if got != RiskNeutral {
		t.Errorf("nil before: got %v, want RiskNeutral", got)
	}
}

func TestClassifyRisk_SameValue(t *testing.T) {
	// true → true → neutral (no change)
	got := ClassifyRisk("is_encrypted", true, true)
	if got != RiskNeutral {
		t.Errorf("same value: got %v, want RiskNeutral", got)
	}
}

func TestRiskDirection_String(t *testing.T) {
	cases := []struct {
		d    RiskDirection
		want string
	}{
		{RiskNeutral, "neutral"},
		{RiskIncreasing, "increasing"},
		{RiskDecreasing, "decreasing"},
	}
	for _, tc := range cases {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.d, got, tc.want)
		}
	}
}
