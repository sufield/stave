// Package watch implements the continuous integrity monitor.
// It watches an observation directory for new snapshots, runs
// assessment on each arrival, and emits alerts to registered sinks.
package watch

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/sufield/stave/internal/core/ports"
)

// AssessFunc runs a full assessment and returns state + violation count
// + risk signals count + max dwell time. The monitor calls this on
// each new snapshot or interval tick.
type AssessFunc func(ctx context.Context) (state string, violations int, slaBreaches int, maxDwellHours float64, violationIDs []string, err error)

// OwnerResolver resolves the owning team for a violation ID (control:asset).
type OwnerResolver interface {
	ResolveViolation(violationID string) (teamID, teamName, contact, slack, jira string)
}

// Config holds the monitor configuration.
type Config struct {
	ObservationsDir string
	Interval        time.Duration
	Sinks           []ports.AlertSink
	Assess          AssessFunc
	Logger          *slog.Logger
	Clock           ports.Clock
	OwnerResolver   OwnerResolver
}

// Monitor runs the continuous assessment loop. The mutex protects
// runCycle's state read/write because file-write debounce timers
// fire runCycle on their own goroutine while the ticker / event
// loop also calls runCycle from the main goroutine. The atomic
// running flag coalesces overlapping triggers: if a new debounce
// timer fires while a previous cycle is still running, the new
// trigger is dropped instead of queueing behind the mutex —
// otherwise a slow assessment plus a burst of file writes could
// pile up an unbounded backlog of cycles all observing nearly the
// same input.
type Monitor struct {
	cfg           Config
	mu            sync.Mutex
	running       atomic.Bool
	previousState string
	previousIDs   map[string]bool
}

// New creates a new Monitor. A nil cfg.Clock is replaced with
// ports.RealClock so the monitor never nil-derefs in runCycle —
// tests that want to control time still need to set Clock
// explicitly.
func New(cfg Config) *Monitor {
	if cfg.Clock == nil {
		cfg.Clock = ports.RealClock{}
	}
	return &Monitor{
		cfg:         cfg,
		previousIDs: make(map[string]bool),
	}
}

// Run starts the watch loop. Blocks until context is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	// Cleanup must run on every exit path — including the early
	// returns from fsnotify.NewWatcher / watcher.Add — so the
	// AlertSinks (which may hold open file handles, network
	// connections, or background goroutines) are released. The
	// previous shape only closed sinks in the ctx.Done() branch,
	// which leaked them on failure paths.
	defer m.closeSinks()

	// Initial assessment.
	m.runCycle(ctx)

	// Start fsnotify watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	if err := watcher.Add(m.cfg.ObservationsDir); err != nil {
		return fmt.Errorf("watch %s: %w", m.cfg.ObservationsDir, err)
	}

	// Interval ticker as fallback.
	var ticker *time.Ticker
	if m.cfg.Interval > 0 {
		ticker = time.NewTicker(m.cfg.Interval)
		defer ticker.Stop()
	}

	var debounce *time.Timer
	defer func() {
		// Stop the debounce timer on shutdown so its scheduled
		// runCycle goroutine doesn't fire after the sinks are
		// closed and the context is cancelled.
		if debounce != nil {
			debounce.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil

		case event := <-watcher.Events:
			if !isObservationFile(event.Name) {
				continue
			}
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				// Debounce: wait 500ms after last write before processing.
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(500*time.Millisecond, func() {
					m.runCycle(ctx)
				})
			}

		case err := <-watcher.Errors:
			if m.cfg.Logger != nil {
				m.cfg.Logger.Warn("watcher error", "error", err)
			}

		case <-tickerChan(ticker):
			m.runCycle(ctx)
		}
	}
}

func (m *Monitor) runCycle(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	// Coalesce: if a previous cycle is still running, drop this
	// trigger entirely rather than queueing behind the mutex. The
	// next debounce/tick will pick up whatever changed between the
	// drop and that next trigger.
	if !m.running.CompareAndSwap(false, true) {
		return
	}
	defer m.running.Store(false)

	// Serialize state mutation across the ticker, fsnotify-debounce
	// timer, and initial-run paths. Held for the full cycle so two
	// concurrent cycles produce sequential state transitions instead
	// of interleaved ones.
	m.mu.Lock()
	defer m.mu.Unlock()

	state, violations, slaBreaches, maxDwell, violationIDs, err := m.cfg.Assess(ctx)
	now := m.cfg.Clock.Now().UTC()

	if err != nil {
		alert := ports.WatchAlert{
			Timestamp:     now,
			Transition:    ports.TransitionError,
			SecurityState: "ERROR",
			ErrorMessage:  err.Error(),
		}
		m.emit(ctx, alert)
		return
	}

	// Build current violation ID set.
	currentIDs := make(map[string]bool, len(violationIDs))
	for _, id := range violationIDs {
		currentIDs[id] = true
	}

	// Detect regressions (new violations not in previous).
	var regressions []string
	newCount := 0
	for _, id := range violationIDs {
		if !m.previousIDs[id] {
			regressions = append(regressions, id)
			newCount++
		}
	}

	// Determine transition.
	transition := m.classifyTransition(state, violations, newCount)

	alert := ports.WatchAlert{
		Timestamp:         now,
		Transition:        transition,
		SecurityState:     state,
		Violations:        violations,
		NewViolations:     newCount,
		Regressions:       regressions,
		ActiveSLABreaches: slaBreaches,
		MaxDwellTimeHours: maxDwell,
	}

	// Annotate owner from the first regression (if team manifest loaded).
	if m.cfg.OwnerResolver != nil && len(regressions) > 0 {
		tid, tname, contact, slack, jira := m.cfg.OwnerResolver.ResolveViolation(regressions[0])
		alert.OwnerTeamID = tid
		alert.OwnerTeamName = tname
		alert.OwnerContact = contact
		alert.OwnerSlackChannel = slack
		alert.OwnerJiraProject = jira
	}

	m.emit(ctx, alert)

	// Update state for next cycle.
	m.previousState = state
	m.previousIDs = currentIDs
}

func (m *Monitor) classifyTransition(state string, _, newCount int) ports.WatchTransition {
	if m.previousState == "" {
		return ports.TransitionInitial
	}

	prevCompliant := m.previousState == "COMPLIANT"
	currCompliant := state == "COMPLIANT"

	switch {
	case prevCompliant && !currCompliant:
		return ports.TransitionRegression
	case !prevCompliant && currCompliant:
		return ports.TransitionRecovery
	case newCount > 0:
		return ports.TransitionDegradation
	default:
		return ports.TransitionStable
	}
}

func (m *Monitor) emit(ctx context.Context, alert ports.WatchAlert) {
	for _, sink := range m.cfg.Sinks {
		if err := sink.Emit(ctx, alert); err != nil && m.cfg.Logger != nil {
			m.cfg.Logger.Warn("alert sink error", "error", err)
		}
	}
}

func (m *Monitor) closeSinks() {
	for _, sink := range m.cfg.Sinks {
		_ = sink.Close()
	}
}

func isObservationFile(name string) bool {
	return strings.HasSuffix(filepath.Base(name), ".json")
}

func tickerChan(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}
