package logging

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/sanitize/scrub"
)

func TestLevelFromVerbosity(t *testing.T) {
	tests := []struct {
		verbosity int
		expected  slog.Level
	}{
		{0, LevelWarn},
		{1, LevelInfo},
		{2, LevelDebug},
		{3, LevelDebug}, // 3+ still debug
		{10, LevelDebug},
	}

	for _, tt := range tests {
		got := LevelFromVerbosity(tt.verbosity)
		if got != tt.expected {
			t.Errorf("LevelFromVerbosity(%d) = %v, want %v", tt.verbosity, got, tt.expected)
		}
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{" Info ", LevelInfo},
		{"warn", LevelWarn},
		{"WARNING", LevelWarn},
		{"error", LevelError},
		{"ErRoR", LevelError},
		{"invalid", LevelWarn}, // default to warn
		{"", LevelWarn},
	}

	for _, tt := range tests {
		got := ParseLevel(tt.input)
		if got != tt.expected {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected Format
	}{
		{"json", FormatJSON},
		{" JSON ", FormatJSON},
		{"text", FormatText},
		{"invalid", FormatText}, // default to text
		{"", FormatText},
	}

	for _, tt := range tests {
		got := ParseFormat(tt.input)
		if got != tt.expected {
			t.Errorf("ParseFormat(%q) = %v, want %v", tt.input, got, tt.expected)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Format != FormatText {
		t.Errorf("DefaultConfig().Format = %v, want %v", cfg.Format, FormatText)
	}
	if cfg.Level != LevelWarn {
		t.Errorf("DefaultConfig().Level = %v, want %v", cfg.Level, LevelWarn)
	}
	if cfg.Timestamps {
		t.Error("DefaultConfig().Timestamps should be false")
	}
	if cfg.Timings {
		t.Error("DefaultConfig().Timings should be false")
	}
}

func TestNewLogger_TextFormat(t *testing.T) {
	cfg := Config{
		Format:     FormatText,
		Level:      LevelInfo,
		Timestamps: false,
	}

	lc, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer func() { _ = lc.Close() }()

	if lc.Logger == nil {
		t.Error("NewLogger returned nil logger")
	}
}

func TestNewLogger_JSONFormat(t *testing.T) {
	cfg := Config{
		Format:     FormatJSON,
		Level:      LevelInfo,
		Timestamps: false,
	}

	lc, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	defer func() { _ = lc.Close() }()

	if lc.Logger == nil {
		t.Error("NewLogger returned nil logger")
	}
}

func TestNewLogger_LogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	cfg := Config{
		Format:  FormatText,
		Level:   LevelInfo,
		LogFile: logFile,
	}

	lc, err := NewLogger(cfg)
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}

	lc.Logger.Info("test message")
	_ = lc.Close()

	// Verify file was created and has content
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	if len(data) == 0 {
		t.Error("Log file is empty")
	}
	if !strings.Contains(string(data), "test message") {
		t.Error("Log file doesn't contain expected message")
	}
}

func TestNewLogger_DeterministicOutput(t *testing.T) {
	// Create a custom handler that writes to a buffer
	var buf bytes.Buffer

	cfg := Config{
		Format:     FormatText,
		Level:      LevelInfo,
		Timestamps: false, // Deterministic
	}

	// Create logger that writes to buffer
	opts := &slog.HandlerOptions{
		Level:       cfg.Level,
		ReplaceAttr: cfg.Scrub,
	}
	handler := slog.NewTextHandler(&buf, opts)
	logger := slog.New(handler)

	// Log a message
	logger.Info("deterministic test", "field", "value")

	output := buf.String()

	// Verify no timestamp in output
	if strings.Contains(output, "time=") {
		t.Errorf("Output contains timestamp when timestamps disabled: %s", output)
	}

	// Verify key-value is present
	if !strings.Contains(output, "field=value") {
		t.Errorf("Output missing key-value: %s", output)
	}
}

func TestNewLogger_WithTimestamps(t *testing.T) {
	var buf bytes.Buffer

	cfg := Config{
		Format:     FormatText,
		Level:      LevelInfo,
		Timestamps: true, // Enable timestamps
	}

	opts := &slog.HandlerOptions{
		Level:       cfg.Level,
		ReplaceAttr: cfg.Scrub,
	}
	handler := slog.NewTextHandler(&buf, opts)
	logger := slog.New(handler)

	logger.Info("timestamp test")

	output := buf.String()

	// Verify timestamp is present when enabled
	if !strings.Contains(output, "time=") {
		t.Errorf("Output missing timestamp when timestamps enabled: %s", output)
	}
}

func TestNewLogger_RedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer

	cfg := Config{
		Format:     FormatText,
		Level:      LevelInfo,
		Timestamps: false,
	}

	opts := &slog.HandlerOptions{
		Level:       cfg.Level,
		ReplaceAttr: cfg.Scrub,
	}

	logger := slog.New(slog.NewTextHandler(&buf, opts))
	logger.Info("sanitize test", "api_token", "abc123", "field", "ok")

	output := buf.String()
	if strings.Contains(output, "abc123") {
		t.Fatalf("sensitive value leaked in output: %s", output)
	}
	if !strings.Contains(output, "api_token="+scrub.SanitizedValue) {
		t.Fatalf("sensitive field not sanitized: %s", output)
	}
	if !strings.Contains(output, "field=ok") {
		t.Fatalf("non-sensitive field unexpectedly changed: %s", output)
	}
}

func TestSetDefaultLogger(t *testing.T) {
	original := DefaultLogger()
	t.Cleanup(func() {
		SetDefaultLogger(original)
	})

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	SetDefaultLogger(logger)

	got := DefaultLogger()
	if got != logger {
		t.Fatalf("DefaultLogger() mismatch: got %p want %p", got, logger)
	}
}

func TestWithRunID(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewTextHandler(&buf, nil))

	got := WithRunID(base, "abc123")
	if got == nil {
		t.Fatal("WithRunID returned nil logger")
	}
	got.Info("run id context")

	output := buf.String()
	if !strings.Contains(output, RunIDKey+"=abc123") {
		t.Fatalf("output missing run_id context: %s", output)
	}
}

func TestWithRunID_EmptyIDReturnsBase(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewTextHandler(&buf, nil))

	got := WithRunID(base, "   ")
	if got != base {
		t.Fatal("WithRunID should return base logger when runID is empty")
	}
	got.Info("no run id")

	output := buf.String()
	if strings.Contains(output, RunIDKey+"=") {
		t.Fatalf("unexpected run_id in output: %s", output)
	}
}

func TestScrub_SourcePathSanitized(t *testing.T) {
	cfg := Config{FullPaths: false}

	attr := slog.Any(slog.SourceKey, &slog.Source{
		File: "/tmp/work/internal/pkg/file.go",
		Line: 42,
	})
	got := cfg.Scrub(nil, attr)
	src, ok := got.Value.Any().(*slog.Source)
	if !ok || src == nil {
		t.Fatalf("expected *slog.Source, got %T", got.Value.Any())
	}
	if src.File != "file.go" {
		t.Fatalf("expected base filename, got %q", src.File)
	}
}

func TestScrub_SourcePathPreservedWhenFullPaths(t *testing.T) {
	cfg := Config{FullPaths: true}

	attr := slog.Any(slog.SourceKey, &slog.Source{
		File: "/tmp/work/internal/pkg/file.go",
		Line: 42,
	})
	got := cfg.Scrub(nil, attr)
	src, ok := got.Value.Any().(*slog.Source)
	if !ok || src == nil {
		t.Fatalf("expected *slog.Source, got %T", got.Value.Any())
	}
	if src.File != "/tmp/work/internal/pkg/file.go" {
		t.Fatalf("expected full path preserved, got %q", src.File)
	}
}

func TestLogCloser_StderrCloseIsNoop(t *testing.T) {
	lc, err := NewLogger(Config{Format: FormatText, Level: LevelWarn})
	if err != nil {
		t.Fatalf("NewLogger failed: %v", err)
	}
	if err := lc.Close(); err != nil {
		t.Errorf("Close() returned error for stderr logger: %v", err)
	}
}
