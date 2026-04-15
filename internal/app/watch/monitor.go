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

// Monitor runs the continuous assessment loop.
type Monitor struct {
	cfg           Config
	previousState string
	previousIDs   map[string]bool
}

// New creates a new Monitor.
func New(cfg Config) *Monitor {
	return &Monitor{
		cfg:         cfg,
		previousIDs: make(map[string]bool),
	}
}

// Run starts the watch loop. Blocks until context is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
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
	for {
		select {
		case <-ctx.Done():
			m.closeSinks()
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
