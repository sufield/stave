package trendcmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/forecast"
	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/app/trendpredict"
	"github.com/sufield/stave/pkg/stave/internal/cmderr"
)

func TestRenderTrend_KnownFormats(t *testing.T) {
	rep := &trendReport{}
	for _, format := range []string{"json", "openmetrics", "executive-summary", "table", ""} {
		var buf bytes.Buffer
		if err := renderTrend(format, &buf, rep); err != nil {
			t.Errorf("renderTrend(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderTrend(%q) produced empty output", format)
		}
	}
}

func TestRenderTrend_UnknownFormatErrors(t *testing.T) {
	err := renderTrend("xml", &bytes.Buffer{}, &trendReport{})
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
	// The main trend command never wrapped its format error, so it must NOT
	// be an InputError (which the facade would map to exit 2).
	if _, ok := errors.AsType[*cmderr.InputError](err); ok {
		t.Error("renderTrend format error must be plain (exit 4), not InputError")
	}
}

func TestRenderForecast_KnownFormats(t *testing.T) {
	for _, format := range []string{"json", "table", ""} {
		var buf bytes.Buffer
		if err := renderForecast(format, &buf, &forecast.Result{}); err != nil {
			t.Errorf("renderForecast(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderForecast(%q) produced empty output", format)
		}
	}
}

func TestRenderForecast_UnknownFormatIsInputError(t *testing.T) {
	err := renderForecast("xml", &bytes.Buffer{}, &forecast.Result{})
	if _, ok := errors.AsType[*cmderr.InputError](err); !ok {
		t.Fatalf("expected *cmderr.InputError, got %T", err)
	}
}

func TestRenderOscillation_KnownFormats(t *testing.T) {
	for _, format := range []string{"json", "table", ""} {
		var buf bytes.Buffer
		if err := renderOscillation(format, &buf, []oscillation.Classification{}); err != nil {
			t.Errorf("renderOscillation(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderOscillation(%q) produced empty output", format)
		}
	}
}

func TestRenderOscillation_UnknownFormatIsInputError(t *testing.T) {
	err := renderOscillation("xml", &bytes.Buffer{}, nil)
	if _, ok := errors.AsType[*cmderr.InputError](err); !ok {
		t.Fatalf("expected *cmderr.InputError, got %T", err)
	}
}

func TestRenderPredict_KnownFormats(t *testing.T) {
	for _, format := range []string{"json", "text", ""} {
		var buf bytes.Buffer
		if err := renderPredict(format, &buf, &trendpredict.Prediction{}); err != nil {
			t.Errorf("renderPredict(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderPredict(%q) produced empty output", format)
		}
	}
}

func TestRenderPredict_UnknownFormatIsInputError(t *testing.T) {
	err := renderPredict("xml", &bytes.Buffer{}, &trendpredict.Prediction{})
	if _, ok := errors.AsType[*cmderr.InputError](err); !ok {
		t.Fatalf("expected *cmderr.InputError, got %T", err)
	}
}
