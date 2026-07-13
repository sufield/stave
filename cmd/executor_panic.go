package cmd

import (
	"fmt"
	"log/slog"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
)

func (a *App) recoverExecutePanic() {
	if recovered := recover(); recovered != nil {
		stack := debug.Stack()

		panicMsg := panicMessageFromValue(recovered)
		sanitized := a.sanitizeExecuteMessage(panicMsg)

		// Match handleExecutionError: bootstrap failures can panic
		// before the structured logger is wired, so fall back to
		// slog.Default() rather than dropping the trace silently.
		// A panic that goes unlogged is the worst case for triage.
		logger := a.Logger
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("panic recovered",
			"panic", sanitized,
			"stack", string(stack),
		)

		// Stop signal delivery and unblock the signal-handler
		// goroutine before starting cleanup. This eliminates the race window
		// where a SIGINT could fire while we are cleaning up, which would
		// see a.cancel as nil and trigger a pre-bootstrap interrupt exit (130)
		// instead of the intended internal error exit (4).
		//
		// Atomic Swap so the deferred normal-path cleanup in Execute
		// observes nil here and skips calling the closure twice.
		if fn := a.cleanupInterrupt.Swap(nil); fn != nil {
			(*fn)()
		}

		// postRun is skipped on panic-recovery, so stop any active CPU
		// profile and flush the log file before exit. cleanupBeforeExit
		// captures both in one place handleExecutionError shares.
		a.cleanupBeforeExit()

		errInfo := a.buildPanicErrorInfo(sanitized)
		a.writeErrorInfo(errInfo)

		a.exit(ui.ExitInternal)
	}
}

func (a *App) buildPanicErrorInfo(sanitized string) *ui.ErrorInfo {
	userMsg := "internal error occurred; rerun with -vv to see details"
	if a.Flags.Verbosity >= 2 {
		userMsg = "internal error: " + sanitized
	}

	action := "Rerun with -vv and report the error at " + metadata.IssuesRef() + " if it persists."
	if a.Edition == EditionDev {
		action = "Rerun with -vv, then run `stave-dev doctor` to diagnose if this error persists."
	}

	return ui.NewErrorInfo(ui.CodeInternalError, userMsg).
		WithTitle("Internal error").
		WithAction(action).
		WithURL(metadata.IssuesRef())
}

func panicMessageFromValue(recovered any) string {
	switch value := recovered.(type) {
	case error:
		return value.Error()
	case string:
		return value
	default:
		return fmt.Sprintf("(panic: %v, type %T)", recovered, recovered)
	}
}

// sanitizeExecuteMessage redacts panic message contents before they
// reach the structured log. The sanitizer is initialized in bootstrap
// phaseLogging — a panic in an earlier phase (validate, config,
// context) reaches here with a nil sanitizer.
//
// Security note: when the operator passed --sanitize but the panic
// fired before bootstrap could wire the sanitizer, returning the raw
// message would leak the very identifiers --sanitize was meant to
// protect. Apply a conservative fallback redactor that strips the
// patterns most likely to carry sensitive data — bucket ARNs, account
// IDs, IP addresses, file paths — so the panic event can still be
// logged without disclosing what the operator explicitly asked to be
// hidden. Operators who did not request sanitization see the raw
// message unchanged.
//
// The bootstrap pipeline wires a.sanitizer unconditionally, so the
// flag check below is what distinguishes "sanitization requested" from
// "sanitizer happens to exist." Without it, every error message had
// its user-supplied paths redacted to `<redacted>` regardless of the
// flag — making first-time debugging impossible because the user
// could not see the path they had just typed.
func (a *App) sanitizeExecuteMessage(message string) string {
	if !a.Flags.Sanitize {
		return message
	}
	if a.sanitizer != nil {
		return a.sanitizer.ScrubMessage(message)
	}
	return fallbackScrubMessage(message)
}

// fallbackScrubMessage applies a minimal set of redactions for the
// pre-bootstrap panic path. Conservative on purpose — better to over-
// redact in this rare path than to leak through it.
var fallbackScrubPatterns = []*regexp.Regexp{
	regexp.MustCompile(`arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"'<>]+`),
	regexp.MustCompile(`\b\d{12}\b`), // account IDs
	// Absolute paths: at least one `/segment/` followed by a non-slash
	// terminal segment. The earlier `{2,}` minimum required two
	// intermediate components, so single-deep paths like `/etc/passwd`
	// or `/tmp/foo` slipped through unredacted in the pre-bootstrap
	// panic path. `+` matches both shallow and deep paths.
	regexp.MustCompile(`/(?:[^/\s:"'<>]+/)+[^/\s:"'<>]+`),
}

// ipv4Candidate matches a four-octet dotted candidate. The regex is
// permissive on its own: each octet is 1-3 digits without range
// validation. The accompanying scrubber routine rejects matches that
// fail octet-range validation (any octet > 255) or that look like
// software version strings (preceded by `v` or followed by another
// dotted numeric segment, suggesting a fifth piece). The earlier
// shape was a single `\b\d{1,3}(?:\.\d{1,3}){3}\b` that produced
// false-positives on version strings (`1.12.3.4` → `[REDACTED]`)
// and false-negatives on URL-embedded IPs (`10.0.0.1:8080` was
// caught only because `:` is not `\w`, but `https://10.0.0.1` has
// alphanumeric context that `\b` already ignores).
var ipv4Candidate = regexp.MustCompile(`(\bv?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\.\d+)?`)

func fallbackScrubMessage(s string) string {
	// Octet-validated IPv4 redaction first so the absolute-path
	// regex below can't eat an IP-looking suffix.
	s = ipv4Candidate.ReplaceAllStringFunc(s, func(m string) string {
		groups := ipv4Candidate.FindStringSubmatch(m)
		if len(groups) < 4 {
			return m
		}
		// Version-string heuristics:
		//   - `v` prefix (group 1 == "v"): treat as a version.
		//   - Trailing `.<digits>` (group 3 non-empty): suggests a
		//     5+ segment number, also a version.
		if groups[1] == "v" || groups[3] != "" {
			return m
		}
		// Octet range validation: every part must fit 0..255 to
		// be a real IPv4.
		for octet := range strings.SplitSeq(groups[2], ".") {
			n, err := strconv.Atoi(octet)
			if err != nil || n > 255 {
				return m
			}
		}
		// groups[3] (trailing .digits) is empty for normal IPv4-like
		// matches but a defensive concatenation preserves any
		// non-sensitive suffix that survives the version-string
		// early-return — keeps grammar around the redaction point
		// intact rather than silently truncating the original input.
		return groups[1] + "[REDACTED]" + groups[3]
	})
	for _, re := range fallbackScrubPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
