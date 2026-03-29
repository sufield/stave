package securityaudit

import "testing"

func TestAllReportFormats(t *testing.T) {
	formats := AllReportFormats()
	if len(formats) != 3 {
		t.Fatalf("AllReportFormats() len=%d, want 3", len(formats))
	}
	want := []string{"json", "markdown", "sarif"}
	for i, f := range formats {
		if f != want[i] {
			t.Fatalf("AllReportFormats()[%d]=%q, want %q", i, f, want[i])
		}
	}
}

func TestStatus_String(t *testing.T) {
	tests := []struct {
		s    Status
		want string
	}{
		{StatusPass, "PASS"},
		{StatusWarn, "WARN"},
		{StatusFail, "FAIL"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Fatalf("Status(%q).String()=%q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestSeverity_Rank(t *testing.T) {
	tests := []struct {
		s    Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{SeverityNone, 0},
		{Severity("UNKNOWN"), 0},
	}
	for _, tt := range tests {
		if got := tt.s.Rank(); got != tt.want {
			t.Fatalf("Severity(%q).Rank()=%d, want %d", tt.s, got, tt.want)
		}
	}
}

func TestSeverity_String(t *testing.T) {
	if got := SeverityCritical.String(); got != "CRITICAL" {
		t.Fatalf("got %q", got)
	}
}

func TestSeverity_Gte_Comprehensive(t *testing.T) {
	tests := []struct {
		s         Severity
		threshold Severity
		want      bool
	}{
		{SeverityCritical, SeverityCritical, true},
		{SeverityCritical, SeverityHigh, true},
		{SeverityCritical, SeverityNone, true},
		{SeverityHigh, SeverityCritical, false},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityMedium, SeverityMedium, true},
		{SeverityLow, SeverityMedium, false},
		{SeverityLow, SeverityLow, true},
		{SeverityNone, SeverityNone, true},
		{SeverityNone, SeverityLow, false},
	}
	for _, tt := range tests {
		name := string(tt.s) + ">=" + string(tt.threshold)
		t.Run(name, func(t *testing.T) {
			if got := tt.s.Gte(tt.threshold); got != tt.want {
				t.Fatalf("%s.Gte(%s)=%v, want %v", tt.s, tt.threshold, got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		raw     string
		want    Severity
		wantErr bool
	}{
		{"CRITICAL", SeverityCritical, false},
		{"critical", SeverityCritical, false},
		{" High ", SeverityHigh, false},
		{"medium", SeverityMedium, false},
		{"LOW", SeverityLow, false},
		{"NONE", SeverityNone, false},
		{"none", SeverityNone, false},
		{"", SeverityNone, false},
		{"INVALID", "", true},
		{"foo", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := ParseSeverity(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseSeverity(%q) expected error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSeverity(%q) error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("ParseSeverity(%q)=%q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseSeverityList(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []Severity
		wantErr bool
	}{
		{"empty defaults", "", []Severity{SeverityCritical, SeverityHigh}, false},
		{"single", "MEDIUM", []Severity{SeverityMedium}, false},
		{"multiple", "HIGH,LOW", []Severity{SeverityHigh, SeverityLow}, false},
		{"dedup", "HIGH,HIGH,LOW", []Severity{SeverityHigh, SeverityLow}, false},
		{"invalid member", "HIGH,INVALID", nil, true},
		{"spaces", " HIGH , LOW ", []Severity{SeverityHigh, SeverityLow}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeverityList(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len=%d, want %d", len(got), len(tt.want))
			}
			for i, s := range got {
				if s != tt.want[i] {
					t.Fatalf("[%d]=%q, want %q", i, s, tt.want[i])
				}
			}
		})
	}
}

func TestAllSeverityStrings(t *testing.T) {
	got := AllSeverityStrings()
	want := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d", len(got), len(want))
	}
	for i, s := range got {
		if s != want[i] {
			t.Fatalf("[%d]=%q, want %q", i, s, want[i])
		}
	}
}

func TestCheckID_String(t *testing.T) {
	if got := CheckBuildInfoPresent.String(); got != "SC.BUILDINFO.PRESENT" {
		t.Fatalf("got %q", got)
	}
}

func TestAllCheckIDs(t *testing.T) {
	ids := AllCheckIDs()
	if len(ids) == 0 {
		t.Fatal("AllCheckIDs() returned empty")
	}
	if len(ids) != len(allChecks) {
		t.Fatalf("len=%d, want %d", len(ids), len(allChecks))
	}
	// Verify defensive copy: mutating returned slice should not affect internal registry.
	ids[0] = "MUTATED"
	fresh := AllCheckIDs()
	if fresh[0] == "MUTATED" {
		t.Fatal("AllCheckIDs did not return a defensive copy")
	}
}
