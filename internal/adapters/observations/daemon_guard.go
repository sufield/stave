package observations

import (
	"context"
	"errors"
)

// daemonContextKey marks a context as belonging to a daemon-style
// long-running caller. CLI one-shots leave this unset; daemon entry
// points (a future watch loop, server, or scheduled-evaluation
// service) must set it via DaemonContext so downstream loaders can
// refuse to run goroutine-leaking code paths.
type daemonContextKey struct{}

// ErrDaemonUnsafe is returned by daemon-unsafe loaders (the bundle
// reader and the stdin reader) when invoked under a context that
// was tagged via DaemonContext. The loaders cannot interrupt their
// blocking reads on ctx cancellation, so accumulating leaked
// goroutines per-iteration would degrade a long-running process.
// Daemon callers must use a deadline-capable input path
// (file-backed loader with SetReadDeadline-aware fd or a wrapper
// that closes the underlying fd on cancellation) instead.
var ErrDaemonUnsafe = errors.New("observations: loader is DAEMON-UNSAFE; goroutine may leak when ctx is cancelled before disk read returns")

// DaemonContext returns a context tagged as a daemon-mode caller.
// Daemon entry points wrap the inbound context once at startup; the
// tag propagates to every observation-load call site so the loader
// guards refuse to run rather than silently leaking a read goroutine
// per cancellation.
func DaemonContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, daemonContextKey{}, true)
}

// isDaemonContext reports whether the context was tagged via
// DaemonContext. Used by the daemon-unsafe loaders to fail-fast
// before kicking off the leakable goroutine.
func isDaemonContext(ctx context.Context) bool {
	v, _ := ctx.Value(daemonContextKey{}).(bool)
	return v
}
