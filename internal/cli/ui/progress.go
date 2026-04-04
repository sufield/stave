package ui

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// CountedProgress reports file-level progress to stderr with file counts.
// Update() is safe for concurrent use. Done() is safe to call multiple times.
// A nil *CountedProgress is valid and all methods are no-ops.
type CountedProgress struct {
	mu         sync.Mutex
	label      string
	processed  int
	total      int
	start      time.Time
	errOut     io.Writer
	isTTY      bool
	stopCh     chan struct{}
	finishedCh chan struct{}
	once       sync.Once // guards Done to prevent double-close of stopCh
}

// Update reports the current progress. Safe to call concurrently.
func (cp *CountedProgress) Update(processed, total int) {
	if cp == nil {
		return
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	// Check if already done via the stop channel (non-blocking).
	select {
	case <-cp.stopCh:
		return
	default:
	}
	cp.processed = processed
	cp.total = total
}

// Done stops the progress display and prints a completion message.
// Safe to call from multiple goroutines; only the first call has effect.
func (cp *CountedProgress) Done() {
	if cp == nil {
		return
	}
	cp.once.Do(func() {
		cp.finishProgress()
	})
}

func (cp *CountedProgress) finishProgress() {
	elapsed := time.Since(cp.start).Round(time.Millisecond)
	cp.mu.Lock()
	total := cp.total
	cp.mu.Unlock()

	if cp.isTTY {
		close(cp.stopCh)
		<-cp.finishedCh
	}

	suffix := fmt.Sprintf(" (%d files, %s)", total, elapsed)
	if total == 0 {
		suffix = fmt.Sprintf(" (%s)", elapsed)
	}

	if cp.isTTY {
		_, _ = fmt.Fprintf(cp.errOut, "\r\033[KDone:    %s%s\n", cp.label, suffix)
	} else {
		_, _ = fmt.Fprintf(cp.errOut, "Done:    %s%s\n", cp.label, suffix)
	}
}

func (cp *CountedProgress) renderLoop() {
	defer close(cp.finishedCh)
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(cp.errOut, "\rprogress render panic: %v\n", r)
		}
	}()
	frames := []string{"|", "/", "-", "\\"}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-cp.stopCh:
			return
		case <-ticker.C:
			cp.mu.Lock()
			p := cp.processed
			t := cp.total
			cp.mu.Unlock()
			if t > 0 {
				_, _ = fmt.Fprintf(cp.errOut, "\r\033[K%s %s [%d/%d]...", frames[i%len(frames)], cp.label, p, t)
			} else {
				_, _ = fmt.Fprintf(cp.errOut, "\r\033[K%s %s...", frames[i%len(frames)], cp.label)
			}
			i++
		}
	}
}

// BeginCountedProgress starts a progress display that shows file counts.
// Call Update() to report progress, and Done() when complete.
// Returns nil (safe no-op) if quiet mode is enabled.
func (r *Runtime) BeginCountedProgress(label string) *CountedProgress {
	if r == nil || r.Quiet {
		return nil
	}

	errOut := r.stderr()
	cp := &CountedProgress{
		label:  label,
		start:  time.Now(),
		errOut: errOut,
		isTTY:  r.isTerminal(errOut),
	}

	if !cp.isTTY {
		_, _ = fmt.Fprintf(errOut, "Running: %s...\n", label)
		return cp
	}

	cp.stopCh = make(chan struct{})
	cp.finishedCh = make(chan struct{})
	go cp.renderLoop()
	return cp
}
