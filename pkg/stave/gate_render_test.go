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
