package diff

import (
	"testing"
)

func TestClassifyRisk_NestedFieldPath(t *testing.T) {
	t.Parallel()

	field := "properties.storage.is_encrypted"
	got := ClassifyRisk(field, true, false)
	if got != RiskIncreasing {
		t.Errorf("CRITICAL BUG: ClassifyRisk(%q, true, false) = %v, want %v; failed to extract leaf field name from dot path", field, got, RiskIncreasing)
	}

	fieldExposure := "properties.access.public_read"
	gotExposure := ClassifyRisk(fieldExposure, false, true)
	if gotExposure != RiskIncreasing {
		t.Errorf("CRITICAL BUG: ClassifyRisk(%q, false, true) = %v, want %v; failed to extract leaf field name from dot path", fieldExposure, gotExposure, RiskIncreasing)
	}
}
