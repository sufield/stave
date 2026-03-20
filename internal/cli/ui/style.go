package ui

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
)

var (
	ansiCodes = map[string]string{
		"error":   "\x1b[31m",
		"warning": "\x1b[33m",
		"success": "\x1b[32m",
		"info":    "\x1b[34m",
		"reset":   "\x1b[0m",
	}

	// map[uintptr]bool, keyed by *os.File pointer address.
	ttyCache sync.Map

	detectTTY = func(f *os.File) bool {
		info, err := f.Stat()
		if err != nil {
			return false
		}
		return (info.Mode() & os.ModeCharDevice) != 0
	}
)

func severityDecor(level string) (symbol, colorCode string) {
	symbol = "[INFO]"
	colorCode = ansiCodes["info"]
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error", "err":
		symbol = "[ERR]"
		colorCode = ansiCodes["error"]
	case "warning", "warn":
		symbol = "[WARN]"
		colorCode = ansiCodes["warning"]
	case "success", "ok":
		symbol = "[OK]"
		colorCode = ansiCodes["success"]
	case "info":
		symbol = "[INFO]"
		colorCode = ansiCodes["info"]
	}
	return symbol, colorCode
}

func renderSeverityLabel(level, message string, canColor bool) string {
	symbol, colorCode := severityDecor(level)
	if !canColor {
		return fmt.Sprintf("%s %s", symbol, message)
	}
	return fmt.Sprintf("%s%s%s %s", colorCode, symbol, ansiCodes["reset"], message)
}

// SeverityLabel formats a message with an ASCII severity marker and optional color.
// Color is enabled only for TTY output when NO_COLOR is not set and TERM is not dumb.
func SeverityLabel(level, message string, out io.Writer) string {
	return renderSeverityLabel(level, message, CanColor(out))
}

// SeverityLabel formats a message using Runtime state and stderr stream by default.
func (r *Runtime) SeverityLabel(level, message string) string {
	if r == nil {
		return SeverityLabel(level, message, os.Stderr)
	}
	return renderSeverityLabel(level, message, r.CanColor(r.stderr()))
}

// CanColor reports whether ANSI color output should be used for this writer.
func CanColor(out io.Writer) bool {
	return DefaultRuntime().CanColor(out)
}

// CanColor reports whether ANSI color output should be used for this writer.
func (r *Runtime) CanColor(out io.Writer) bool {
	if r != nil && r.NoColor {
		return false
	}
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	if strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return false
	}

	if r != nil && r.IsTTY != nil {
		return *r.IsTTY
	}

	f, ok := out.(*os.File)
	if !ok {
		return false
	}

	key := reflect.ValueOf(f).Pointer()
	if cached, ok := ttyCache.Load(key); ok {
		return cached.(bool)
	}

	enabled := detectTTY(f)
	ttyCache.Store(key, enabled)
	return enabled
}
