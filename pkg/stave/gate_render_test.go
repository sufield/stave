package stave

import (
	"strings"
	"testing"
)

func TestParseGateFormat_Known(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"json", "json"},
		{"JSON", "json"},
		{"text", "text"},
		{"", "text"},
		{" text ", "text"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseGateFormat(tc.in)
			if err != nil {
				t.Fatalf("parseGateFormat(%q): unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseGateFormat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseGateFormat_Unknown(t *testing.T) {
	_, err := parseGateFormat("bogus")
	if err == nil {
		t.Fatal("parseGateFormat(\"bogus\"): want error")
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestGateRenderResult_NonEmptyOutput(t *testing.T) {
	result := &GateResult{
		Policy: GateFailOnAnyViolation,
		Passed: true,
		Reason: "no violations",
	}
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			out, err := gateRenderResult(format, false, result)
			if err != nil {
				t.Fatalf("gateRenderResult(%q): unexpected error: %v", format, err)
			}
			if len(out) == 0 {
				t.Errorf("gateRenderResult(%q) produced empty output", format)
			}
		})
	}
}

func TestGateRenderResult_QuietSuppressesText(t *testing.T) {
	result := &GateResult{
		Policy: GateFailOnAnyViolation,
		Passed: true,
		Reason: "no violations",
	}
	out, err := gateRenderResult("text", true, result)
	if err != nil {
		t.Fatalf("gateRenderResult(text, quiet): unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("quiet text render should suppress output, got %q", out)
	}
}

func TestGateRenderResult_JSONAlwaysEmits(t *testing.T) {
	result := &GateResult{Policy: GateFailOnAnyViolation, Passed: true, Reason: "ok"}
	out, err := gateRenderResult("json", true, result)
	if err != nil {
		t.Fatalf("gateRenderResult(json, quiet): unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Error("json render should always emit, even when quiet")
	}
}

func TestGateResult_DomainMethods(t *testing.T) {
	var nilResult *GateResult
	if nilResult.IsPassing() || nilResult.IsFailing() || nilResult.HasViolations() ||
		nilResult.HasNewViolations() || nilResult.HasOverdue() || nilResult.TotalBreaches() != 0 ||
		nilResult.IsClean() || nilResult.PassLabel() != "FAIL" {
		t.Error("nil GateResult should safely return false/zero/FAIL")
	}

	clean := &GateResult{
		Policy:            GateFailOnAnyViolation,
		Passed:            true,
		CurrentViolations: 0,
		NewViolations:     0,
		OverdueCount:      0,
	}
	if !clean.IsPassing() || clean.IsFailing() {
		t.Error("clean result should be passing and not failing")
	}
	if !clean.IsClean() {
		t.Error("clean result should be clean")
	}
	if clean.HasViolations() || clean.HasNewViolations() || clean.HasOverdue() {
		t.Error("clean result should have no violations")
	}
	if clean.TotalBreaches() != 0 {
		t.Errorf("TotalBreaches() = %d, want 0", clean.TotalBreaches())
	}
	if clean.PassLabel() != "PASS" {
		t.Errorf("PassLabel() = %q, want PASS", clean.PassLabel())
	}

	failAny := &GateResult{
		Policy:            GateFailOnAnyViolation,
		Passed:            false,
		CurrentViolations: 5,
	}
	if !failAny.IsFailing() || failAny.IsPassing() {
		t.Error("failAny check failed")
	}
	if !failAny.HasViolations() {
		t.Error("HasViolations() = false, want true")
	}
	if failAny.IsClean() {
		t.Error("failAny should not be clean")
	}
	if failAny.TotalBreaches() != 5 {
		t.Errorf("TotalBreaches() = %d, want 5", failAny.TotalBreaches())
	}
	if failAny.PassLabel() != "FAIL" {
		t.Errorf("PassLabel() = %q, want FAIL", failAny.PassLabel())
	}

	failNew := &GateResult{
		Policy:            GateFailOnNewViolation,
		Passed:            false,
		CurrentViolations: 10,
		NewViolations:     3,
	}
	if !failNew.HasNewViolations() {
		t.Error("HasNewViolations() = false, want true")
	}
	if failNew.TotalBreaches() != 3 {
		t.Errorf("TotalBreaches() = %d, want 3 for GateFailOnNewViolation", failNew.TotalBreaches())
	}

	failOverdue := &GateResult{
		Policy:       GateFailOnOverdueUpcoming,
		Passed:       false,
		OverdueCount: 2,
	}
	if !failOverdue.HasOverdue() {
		t.Error("HasOverdue() = false, want true")
	}
	if failOverdue.TotalBreaches() != 2 {
		t.Errorf("TotalBreaches() = %d, want 2 for GateFailOnOverdueUpcoming", failOverdue.TotalBreaches())
	}
}
