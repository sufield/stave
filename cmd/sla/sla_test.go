package sla

import (
	"bytes"
	"strings"
	"testing"

	infraSLA "github.com/sufield/stave/internal/adapters/sla"
)

func TestInitStdout_Default(t *testing.T) {
	var buf bytes.Buffer
	opts := &initOptions{Profile: "default", Stdout: true}
	if err := runInit(&buf, &bytes.Buffer{}, opts); err != nil {
		t.Fatalf("runInit failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "id: default") {
		t.Error("missing id: default")
	}
	if !strings.Contains(out, "critical: 72h") {
		t.Error("missing critical deadline")
	}
}

func TestInitStdout_AllProfiles(t *testing.T) {
	for _, profile := range []string{"default", "hipaa", "fedramp", "pci", "strict"} {
		t.Run(profile, func(t *testing.T) {
			var buf bytes.Buffer
			opts := &initOptions{Profile: profile, Stdout: true}
			if err := runInit(&buf, &bytes.Buffer{}, opts); err != nil {
				t.Fatalf("profile %s failed: %v", profile, err)
			}
			if buf.Len() == 0 {
				t.Error("empty output")
			}
		})
	}
}

func TestValidate_ValidPolicy(t *testing.T) {
	var buf bytes.Buffer
	opts := &validateOptions{File: "../../internal/adapters/sla/embedded/default.yaml"}
	if err := runValidate(&buf, opts); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "OK") {
		t.Error("expected OK in output")
	}
}

func TestSimulate_Categorizes(t *testing.T) {
	pol := &infraSLA.Policy{
		Name: "test",
		Deadlines: infraSLA.DeadlineTiers{
			Critical: "24h",
			High:     "72h",
			Medium:   "336h",
			Low:      "720h",
		},
		EscalationFactor: 1.5,
	}

	findings := []simFinding{
		{ControlID: "CTL.A", Severity: "critical", DwellHours: 10}, // within (10/24 = 41%)
		{ControlID: "CTL.B", Severity: "critical", DwellHours: 20}, // approaching (20/24 = 83%)
		{ControlID: "CTL.C", Severity: "critical", DwellHours: 48}, // breached (48/24 = 200%)
		{ControlID: "CTL.D", Severity: "high", DwellHours: 60},     // approaching (60/72 = 83%)
	}

	result := simulate(pol, findings)

	if len(result.within) != 1 {
		t.Errorf("within = %d, want 1", len(result.within))
	}
	if len(result.approaching) != 2 {
		t.Errorf("approaching = %d, want 2", len(result.approaching))
	}
	if len(result.breached) != 1 {
		t.Errorf("breached = %d, want 1", len(result.breached))
	}
}
