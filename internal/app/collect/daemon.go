package collect

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DaemonOpts holds configuration for daemon mode.
type DaemonOpts struct {
	Period     time.Duration
	PIDFile    string
	AuditLabel string
	// RunOnce is called for each collection cycle.
	// Injected by the caller to reuse the existing collection logic.
	RunOnce func(ctx context.Context) error
}

// RunDaemon runs the collection loop until SIGTERM or context cancellation.
func RunDaemon(ctx context.Context, opts DaemonOpts) error {
	if opts.RunOnce == nil {
		return errors.New("runOnce function is required")
	}

	// Write PID file.
	if opts.PIDFile != "" {
		pid := strconv.Itoa(os.Getpid())
		if err := os.WriteFile(opts.PIDFile, []byte(pid+"\n"), 0o644); err != nil { //nolint:gosec
			return fmt.Errorf("write pid file: %w", err)
		}
		defer os.Remove(opts.PIDFile)
	}

	// Handle SIGTERM/SIGINT.
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	slog.Info("collect daemon started",
		"period", opts.Period,
		"pid_file", opts.PIDFile,
		"audit_label", opts.AuditLabel)

	for {
		if err := opts.RunOnce(ctx); err != nil {
			// CRITICAL: log and continue — do NOT return.
			slog.Error("collection failed, continuing",
				"error", err,
				"period", opts.Period)
		} else {
			slog.Info("collection complete",
				"period", opts.Period)
		}

		select {
		case <-ctx.Done():
			slog.Info("collect daemon stopping")
			return nil
		case <-time.After(opts.Period):
			// continue to next collection
		}
	}
}

// StatusOpts holds configuration for the status command.
type StatusOpts struct {
	EvidenceDir string
	PIDFile     string
}

// RunStatus reports daemon status and archive coverage.
func RunStatus(opts StatusOpts) string {
	var b strings.Builder

	fmt.Fprintf(&b, "STAVE COLLECT STATUS\n")
	fmt.Fprintf(&b, "Archive: %s\n\n", opts.EvidenceDir)

	// Daemon status from PID file.
	daemonStatus := "NOT RUNNING"
	if opts.PIDFile != "" {
		if data, err := os.ReadFile(opts.PIDFile); err == nil { //nolint:gosec
			pidStr := strings.TrimSpace(string(data))
			pid, _ := strconv.Atoi(pidStr)
			if pid > 0 {
				proc, findErr := os.FindProcess(pid)
				if findErr == nil {
					if sigErr := proc.Signal(syscall.Signal(0)); sigErr == nil {
						daemonStatus = fmt.Sprintf("RUNNING (PID %d)", pid)
					} else {
						daemonStatus = fmt.Sprintf("STOPPED (stale PID %d)", pid)
					}
				}
			}
		}
	}
	fmt.Fprintf(&b, "Daemon: %s\n\n", daemonStatus)

	// List runs from manifest.
	archive := &Archive{Path: opts.EvidenceDir}
	manifest, err := archive.LoadManifest()
	if err != nil || len(manifest.Runs) == 0 {
		fmt.Fprintf(&b, "No bundles found.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "PERIOD COVERAGE (last 10)\n")
	start := max(len(manifest.Runs)-10, 0)
	for i := len(manifest.Runs) - 1; i >= start; i-- {
		r := &manifest.Runs[i]
		fmt.Fprintf(&b, "  %s  ✓  %d findings\n", r.CollectedAt, r.FindingCount)
	}

	if len(manifest.Gaps) > 0 {
		fmt.Fprintf(&b, "\nGAPS: %d detected\n", len(manifest.Gaps))
	} else {
		fmt.Fprintf(&b, "\nNo gaps detected.\n")
	}

	fmt.Fprintf(&b, "\nArchive: %d bundles\n", len(manifest.Runs))
	return b.String()
}
