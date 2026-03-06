package cmd

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/identity"
	"github.com/sufield/stave/internal/platform/logging"
)

func TestAttachRunIDFromPlan(t *testing.T) {
	originalGlobal := globalLogger
	originalDefault := logging.DefaultLogger()
	t.Cleanup(func() {
		globalLogger = originalGlobal
		logging.SetDefaultLogger(originalDefault)
	})

	var buf bytes.Buffer
	globalLogger = slog.New(slog.NewTextHandler(&buf, nil))

	plan := &appeval.EvaluationPlan{
		ObservationsHash: "obs-hash",
		ControlsHash:     "ctl-hash",
	}
	attachRunIDFromPlan(plan)
	globalLogger.Info("test message")

	out := buf.String()
	wantRunID := identity.ComputeRunID(GetVersion(), plan.ObservationsHash.String(), plan.ControlsHash.String())
	if !strings.Contains(out, logging.RunIDKey+"="+wantRunID) {
		t.Fatalf("missing run_id context in log output: %s", out)
	}
}

func TestAttachRunIDFromPlanNil(t *testing.T) {
	originalGlobal := globalLogger
	originalDefault := logging.DefaultLogger()
	t.Cleanup(func() {
		globalLogger = originalGlobal
		logging.SetDefaultLogger(originalDefault)
	})

	var buf bytes.Buffer
	globalLogger = slog.New(slog.NewTextHandler(&buf, nil))

	attachRunIDFromPlan(nil)
	globalLogger.Info("test message")

	out := buf.String()
	if strings.Contains(out, logging.RunIDKey+"=") {
		t.Fatalf("unexpected run_id context for nil plan: %s", out)
	}
}
