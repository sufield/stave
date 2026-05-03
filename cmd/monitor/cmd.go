// Package monitor implements the 'stave monitor' command for a
// terminal security posture display.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	infraSLA "github.com/sufield/stave/internal/adapters/sla"
	appcoverage "github.com/sufield/stave/internal/app/coverage"
	appmon "github.com/sufield/stave/internal/app/monitor"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/capabilities"
	"github.com/sufield/stave/internal/core/report"
)

type options struct {
	HistoryDir string
	SLAFile    string
	Refresh    int
	Format     string
	NoColor    bool
}

// NewCmd constructs the monitor command.
func NewCmd() *cobra.Command {
	opts := &options{
		Refresh: 30,
		Format:  "live",
	}

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Terminal security posture monitor",
		Long: `Display current posture score, top findings, SLA burn rates,
and severity distribution in a single terminal view. Refreshes
automatically at the specified interval.

Formats:
  live    ANSI terminal display with auto-refresh (default)
  json    Single-shot structured output, then exit
  plain   Human-readable text, no ANSI codes

Inputs:
  --history PATH          History directory (required)
  --sla-profile-file PATH SLA policy for burn rate display
  --refresh INT           Refresh interval in seconds (default: 30)

Exit Codes:
  0   Normal exit (q key or signal)
  2   Invalid input
  4   Internal error`,
		Example: `  # Standard monitor
  stave monitor --history ./history

  # With SLA context
  stave monitor --history ./history --sla-profile-file sla.yaml

  # JSON snapshot for scripting
  stave monitor --history ./history --format json

  # Plain text for logging
  stave monitor --history ./history --format plain`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMonitor(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "history directory to monitor (required)")
	cmd.Flags().StringVar(&opts.SLAFile, "sla-profile-file", "", "SLA policy for burn rate display")
	cmd.Flags().IntVar(&opts.Refresh, "refresh", 30, "refresh interval in seconds")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "live", "output format: live | json | plain")
	cmd.Flags().BoolVar(&opts.NoColor, "no-color", false, "disable ANSI color codes")

	_ = cmd.MarkFlagRequired("history")

	return cmd
}

func runMonitor(ctx context.Context, stdout, _ io.Writer, opts *options) error {
	// Load ATT&CK coverage once (static, does not change per refresh).
	attckTactics := loadATTCKTactics()

	loadState := func() (*appmon.State, error) {
		assessments, err := loadAssessments(ctx, opts.HistoryDir)
		if err != nil {
			return nil, err
		}
		if len(assessments) == 0 {
			return nil, fmt.Errorf("no assessment files in %s", opts.HistoryDir)
		}
		chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
		if chainsErr != nil {
			return nil, fmt.Errorf("loading chains: %w", chainsErr)
		}
		var slaDeadlines map[string]float64
		if opts.SLAFile != "" {
			pol, slaErr := infraSLA.LoadFromFile(opts.SLAFile)
			if slaErr != nil {
				// User explicitly named a file — failing silently here
				// would leave SLA deadlines nil with no diagnostic.
				return nil, fmt.Errorf("load sla profile %s: %w", opts.SLAFile, slaErr)
			}
			slaDeadlines = pol.AllDeadlines()
		}
		state := appmon.Build(appmon.BuildInput{
			GeneratedAt:    time.Now().UTC().Format("2006-01-02 15:04:05"),
			Assessments:    assessments,
			ChainDefs:      len(chains),
			MaxChainWeight: appscore.ChainMaxWeight(chains),
			SLADeadlines:   slaDeadlines,
		})
		state.ATTCKTactics = attckTactics
		return state, nil
	}

	switch opts.Format {
	case "json":
		state, err := loadState()
		if err != nil {
			return &ui.UserError{Err: err}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(state)

	case "plain":
		state, err := loadState()
		if err != nil {
			return &ui.UserError{Err: err}
		}
		appmon.RenderPlain(stdout, state, false)
		return nil

	case "live":
		return runLiveLoop(ctx, stdout, opts, loadState)

	default:
		return &ui.UserError{Err: fmt.Errorf("unknown format %q (valid: live, json, plain)", opts.Format)}
	}
}

func runLiveLoop(ctx context.Context, stdout io.Writer, opts *options, loadState func() (*appmon.State, error)) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(time.Duration(opts.Refresh) * time.Second)
	defer ticker.Stop()

	// fsnotify: watch history directory for new files.
	var fsCh <-chan fsnotify.Event
	watcher, watchErr := fsnotify.NewWatcher()
	if watchErr == nil {
		defer func() { _ = watcher.Close() }()
		if addErr := watcher.Add(opts.HistoryDir); addErr != nil {
			// Watcher creation succeeded but the directory could not be
			// added — fall back to ticker-only refresh and tell the
			// user why interactive refresh is degraded.
			fmt.Fprintf(stdout, "Warning: filesystem watch disabled (%v); using --refresh interval only.\n", addErr)
		} else {
			fsCh = watcher.Events
		}
	}
	// If fsnotify unavailable, fsCh is nil — select ignores nil channels.

	// Keyboard: read single bytes from stdin in a goroutine. The
	// done channel signals the goroutine to drop any further read
	// result on the floor when runLiveLoop exits — we cannot
	// portably interrupt the blocked stdin Read syscall (no
	// SetReadDeadline on a TTY across all platforms), so the
	// goroutine still parks on the syscall until the user presses
	// a key or the process terminates. Signaling done at least
	// keeps the goroutine from sending into a channel no one is
	// reading from anymore, which used to leak the goroutine plus
	// one buffered byte for the lifetime of the parent process.
	keyCh := make(chan byte, 1)
	keyDone := make(chan struct{})
	defer close(keyDone)
	if isTerminalFd(os.Stdin.Fd()) {
		go readKeys(keyCh, keyDone)
	}

	// Initial render.
	if err := renderOnce(ctx, stdout, opts, loadState); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-sigCh:
			return nil
		case ev, ok := <-fsCh:
			if ok && ev.Op&fsnotify.Create != 0 && strings.HasSuffix(ev.Name, ".json") {
				// Small delay to let file finish writing.
				time.Sleep(200 * time.Millisecond)
				if err := renderOnce(ctx, stdout, opts, loadState); err != nil {
					if _, werr := fmt.Fprintf(stdout, "\nRefresh error (fsnotify): %v\n", err); werr != nil {
						return werr
					}
				}
			}
		case key := <-keyCh:
			switch key {
			case 'q', 'Q', 3: // q, Q, or Ctrl+C
				return nil
			case 'r', 'R':
				if err := renderOnce(ctx, stdout, opts, loadState); err != nil {
					if _, werr := fmt.Fprintf(stdout, "\nRefresh error (manual): %v\n", err); werr != nil {
						return werr
					}
				}
			}
		case <-ticker.C:
			if err := renderOnce(ctx, stdout, opts, loadState); err != nil {
				// Stdout write failures (broken pipe to a terminal
				// that the user closed, or `stave monitor | head`
				// where head closed early) used to be ignored, so
				// the loop kept running and burning CPU on every
				// tick attempting to write to a dead descriptor.
				// Exiting on the first write failure stops the
				// busy loop.
				if _, werr := fmt.Fprintf(stdout, "\nRefresh error: %v\n", err); werr != nil {
					return werr
				}
			}
		}
	}
}

func readKeys(ch chan<- byte, done <-chan struct{}) {
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		// If runLiveLoop has exited, drop the byte and exit instead
		// of blocking on a send no one is reading. The goroutine
		// effectively wakes up on the next keystroke and notices.
		select {
		case ch <- buf[0]:
		case <-done:
			return
		}
	}
}

// isTerminalFd reports whether the given file descriptor refers to
// a character device (a terminal). The earlier shape ignored the fd
// parameter and always Stat'd os.Stdin, so callers asking about a
// non-stdin fd (e.g. checking stdout for live-display compatibility)
// got the wrong answer when the binary was invoked with stdin
// redirected from a file but stdout still attached to the terminal.
func isTerminalFd(fd uintptr) bool {
	f := os.NewFile(fd, "")
	if f == nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func loadATTCKTactics() []appmon.TacticRow {
	var tactics []appmon.TacticRow
	for _, td := range appcoverage.AllTactics {
		tactics = append(tactics, appmon.TacticRow{
			ID:   td.ID,
			Name: td.Name,
		})
	}
	// Control counts are loaded from catalog — approximate from AllTactics.
	// A full count requires loading all controls, which is expensive.
	// For the monitor, we show tactic names without counts.
	return tactics
}

func renderOnce(_ context.Context, stdout io.Writer, opts *options, loadState func() (*appmon.State, error)) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	appmon.RenderLive(stdout, state, opts.NoColor)
	return nil
}

func loadAssessments(ctx context.Context, dir string) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	loader := artifact.NewLoader()
	var out []*report.Assessment
	var skipped int
	var firstSkipErr error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		a, loadErr := loader.Evaluation(ctx, filepath.Join(dir, e.Name()))
		if loadErr != nil {
			skipped++
			if firstSkipErr == nil {
				firstSkipErr = fmt.Errorf("%s: %w", e.Name(), loadErr)
			}
			continue
		}
		out = append(out, a)
	}
	if skipped > 0 {
		// Surface the count via a slog warning so live mode can render a
		// footer note and json/plain modes log it to stderr; the loader
		// keeps returning the partial list so monitoring degrades
		// gracefully when a single file is corrupt.
		slog.Warn("assessment history: skipped unreadable files",
			"skipped", skipped, "loaded", len(out), "first_error", firstSkipErr)
	}
	return out, nil
}
