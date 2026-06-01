package observations

import "sync/atomic"

// leakedReadGoroutines tracks the number of read goroutines that
// outlived their parent context.Done() because the underlying
// blocking read could not be interrupted. Both BundleLoader and
// StdinObservationLoader spawn such goroutines, and the daemon
// guard rejects calls under DaemonContext, but a CLI run that
// times out mid-read still leaks one goroutine per occurrence.
//
// The counter exists for two purposes:
//   - Diagnostic: operators or test harnesses inspecting a long
//     test run can call LeakedReadGoroutines() to see whether ctx
//     cancellations have been silently dropping goroutines.
//   - Future-fix waypoint: when context.AfterFunc-driven
//     cancellation lands and we replace the spawn pattern, this
//     counter validates that the new path stays at zero across a
//     ctx-cancellation stress test.
//
// Increments happen ONLY on the ctx-cancelled path inside the
// loader; the happy path (read completes before ctx.Done) does
// not touch this counter.
var leakedReadGoroutines atomic.Int64

// recordLeakedReadGoroutine increments the counter. Called by the
// loader on the ctx.Done() branch — the goroutine itself remains
// blocked on the syscall and will eventually exit when the OS
// returns control, but for the duration of the read it is
// genuinely leaked from this process's bookkeeping perspective.
func recordLeakedReadGoroutine() {
	leakedReadGoroutines.Add(1)
}
