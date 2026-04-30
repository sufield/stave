package cmd

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

func (a *App) recoverExecutePanic() {
	if recovered := recover(); recovered != nil {
		stack := debug.Stack()

		panicMsg := panicMessageFromValue(recovered)
		sanitized := a.sanitizeExecuteMessage(panicMsg)

		if a.Logger != nil {
			a.Logger.Error("panic recovered",
				"panic", sanitized,
				"stack", string(stack),
			)
		}

		// postRun is skipped on panic-recovery, so stop any active CPU
		// profile and flush the log file before exit. cleanupBeforeExit
		// captures both in one place handleExecutionError shares.
		a.cleanupBeforeExit()

		errInfo := a.buildPanicErrorInfo(sanitized)
		a.writeErrorInfo(errInfo)

		// Stop signal delivery and unblock the signal-handler
		// goroutine before ExitFunc. In production ExitFunc is os.Exit
		// and the goroutine dies with the process; in tests ExitFunc
		// is mocked, and without this explicit cleanup the handler
		// goroutine stays blocked on its select for the rest of the
		// test run, leaking against future tests.
		//
		// Atomic Swap so the deferred normal-path cleanup in Execute
		// observes nil here and skips calling the closure twice.
		if fn := a.cleanupInterrupt.Swap(nil); fn != nil {
			(*fn)()
		}
		a.ExitFunc(ui.ExitInternal)
	}
}

func (a *App) buildPanicErrorInfo(sanitized string) *ui.ErrorInfo {
	userMsg := "internal error occurred; rerun with -vv to see details"
	if a.Flags.Verbosity >= 2 {
		userMsg = "internal error: " + sanitized
	}

	action := "Rerun with -vv, then run `stave-dev doctor` or contact support if this error persists."
	if a.Edition == EditionDev {
		action = "Rerun with -vv, then run `stave bug-report` and attach the bundle if it persists."
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
		return fmt.Sprintf("(panic type %T)", recovered)
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
func (a *App) sanitizeExecuteMessage(message string) string {
	if a.sanitizer != nil {
		return a.sanitizer.ScrubMessage(message)
	}
	if a.Flags.Sanitize {
		return fallbackScrubMessage(message)
	}
	return message
}

// fallbackScrubMessage applies a minimal set of redactions for the
// pre-bootstrap panic path. Conservative on purpose — better to over-
// redact in this rare path than to leak through it.
var fallbackScrubPatterns = []*regexp.Regexp{
	regexp.MustCompile(`arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s"'<>]+`),
	regexp.MustCompile(`\b\d{12}\b`),                         // account IDs
	regexp.MustCompile(`/(?:[^/\s:"'<>]+/){2,}[^/\s:"'<>]+`), // absolute paths
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
		for _, octet := range strings.Split(groups[2], ".") {
			n, err := strconv.Atoi(octet)
			if err != nil || n > 255 {
				return m
			}
		}
		return groups[1] + "[REDACTED]"
	})
	for _, re := range fallbackScrubPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
