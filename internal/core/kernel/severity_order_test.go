package kernel

import "testing"

func TestSeverityOrder_CriticalBeforeHigh(t *testing.T) {
	if SeverityOrder["critical"] >= SeverityOrder["high"] {
		t.Error("critical should sort before high")
	}
	if SeverityOrder["high"] >= SeverityOrder["medium"] {
		t.Error("high should sort before medium")
	}
	if SeverityOrder["medium"] >= SeverityOrder["low"] {
		t.Error("medium should sort before low")
	}
}

func TestSeverityWeight_CriticalHighestWeight(t *testing.T) {
	if SeverityWeight["critical"] <= SeverityWeight["high"] {
		t.Error("critical should have highest weight")
	}
	if SeverityWeight["high"] <= SeverityWeight["medium"] {
		t.Error("high should weigh more than medium")
	}
	if SeverityWeight["medium"] <= SeverityWeight["low"] {
		t.Error("medium should weigh more than low")
	}
}

func TestParseSeverity_UnknownReturnsLow(t *testing.T) {
	if ParseSeverity("unknown") != "low" {
		t.Errorf("ParseSeverity(unknown) = %q, want low", ParseSeverity("unknown"))
	}
	if ParseSeverity("critical") != "critical" {
		t.Errorf("ParseSeverity(critical) = %q, want critical", ParseSeverity("critical"))
	}
	if ParseSeverity("info") != "info" {
		t.Errorf("ParseSeverity(info) = %q, want info", ParseSeverity("info"))
	}
}
