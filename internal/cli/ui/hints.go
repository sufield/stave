package ui

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/sufield/stave/internal/metadata"
)

// RemediationHint captures actionable guidance for a known error condition.
type RemediationHint struct {
	Reason      string
	NextCommand string
	SearchQuery string
}

var nonQueryToken = regexp.MustCompile(`[^a-z0-9._-]+`)

var sentinelToHint = make(map[error]RemediationHint)

// Sentinel errors used to classify known CLI issues.
var (
	ErrHintControlsNotAccessible     = errors.New("hints: controls not accessible")
	ErrHintObservationsNotAccessible = errors.New("hints: observations not accessible")
	ErrHintInvalidMaxUnsafe          = errors.New("hints: invalid max-unsafe")
	ErrHintNoControls                = errors.New("hints: no controls")
	ErrHintNoSnapshots               = errors.New("hints: no snapshots")
	ErrHintSchemaValidation          = errors.New("hints: schema validation")
	ErrHintSourceType                = errors.New("hints: source_type mismatch")
	ErrHintControlSourceConflict     = errors.New("hints: control source conflict")
)

type hintRule struct {
	err      error
	patterns []string
	hint     RemediationHint
}

// hintRegistry maps sentinel errors to UI hints and fallback message patterns.
var hintRegistry = []hintRule{
	{
		err:      ErrHintControlsNotAccessible,
		patterns: []string{"--controls not accessible"},
		hint: RemediationHint{
			Reason:      "Control directory is missing or unreadable.",
			NextCommand: "stave init --profile mvp1-s3",
			SearchQuery: "init controls directory not accessible",
		},
	},
	{
		err:      ErrHintObservationsNotAccessible,
		patterns: []string{"--observations not accessible"},
		hint: RemediationHint{
			Reason:      "Observation snapshots are missing or unreadable.",
			NextCommand: "stave ingest --profile mvp1-s3 --input ./snapshots/raw/aws-s3 --out ./observations",
			SearchQuery: "ingest observations directory not accessible",
		},
	},
	{
		err:      ErrHintInvalidMaxUnsafe,
		patterns: []string{"invalid --max-unsafe"},
		hint: RemediationHint{
			Reason:      "--max-unsafe value format is invalid.",
			NextCommand: "stave apply --controls ./controls --observations ./observations --max-unsafe 168h",
			SearchQuery: "max-unsafe duration format",
		},
	},
	{
		err:      ErrHintNoControls,
		patterns: []string{"no controls in", "no controls in"},
		hint: RemediationHint{
			Reason:      "No controls found.",
			NextCommand: "stave generate control --id CTL.S3.PUBLIC.901 --out ./controls/CTL.S3.PUBLIC.901.yaml",
			SearchQuery: "create canonical control",
		},
	},
	{
		err:      ErrHintNoSnapshots,
		patterns: []string{"no snapshots in"},
		hint: RemediationHint{
			Reason:      "No observation snapshots found for evaluation.",
			NextCommand: "stave ingest --profile mvp1-s3 --input ./snapshots/raw/aws-s3 --out ./observations",
			SearchQuery: "ingest no snapshots",
		},
	},
	{
		err:      ErrHintSchemaValidation,
		patterns: []string{"schema validation failed"},
		hint: RemediationHint{
			Reason:      "Input files do not conform to schema.",
			NextCommand: "stave validate --controls ./controls --observations ./observations",
			SearchQuery: "validate schema validation failed",
		},
	},
	{
		err:      ErrHintSourceType,
		patterns: []string{"missing generated_by.source_type", "unsupported source_type"},
		hint: RemediationHint{
			Reason:      "Observation source_type is missing or unsupported.",
			NextCommand: "stave apply --controls ./controls --observations ./observations --allow-unknown-input",
			SearchQuery: "allow-unknown-input source_type",
		},
	},
	{
		err:      ErrHintControlSourceConflict,
		patterns: []string{"cannot combine explicit --controls with enabled_control_packs"},
		hint: RemediationHint{
			Reason:      "Two control sources were selected at once (CLI directory and project packs).",
			NextCommand: "stave status",
			SearchQuery: "enabled_control_packs explicit controls conflict",
		},
	},
}

func init() {
	for i := range hintRegistry {
		entry := &hintRegistry[i]
		for j := range entry.patterns {
			entry.patterns[j] = strings.ToLower(entry.patterns[j])
		}
		if entry.err != nil {
			sentinelToHint[entry.err] = entry.hint
		}
	}
}

type hintedError struct {
	hint error
	err  error
}

func (e *hintedError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *hintedError) Unwrap() []error {
	if e == nil {
		return nil
	}
	out := make([]error, 0, 2)
	if e.err != nil {
		out = append(out, e.err)
	}
	if e.hint != nil {
		out = append(out, e.hint)
	}
	return out
}

func (e *hintedError) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	return errors.Is(e.err, target) || errors.Is(e.hint, target)
}

func (e *hintedError) As(target any) bool {
	if e == nil {
		return false
	}
	return errors.As(e.err, target) || errors.As(e.hint, target)
}

// WithHint decorates err with a sentinel hint for later rule matching.
func WithHint(err, hint error) error {
	if err == nil || hint == nil {
		return err
	}
	if errors.Is(err, hint) {
		return err
	}
	return &hintedError{hint: hint, err: err}
}

// WithNextCommand appends a remediation command to an error.
// The "More info" line resolves to a local `stave docs search` reference
// (or the URL in STAVE_DOCS_URL if set).
func WithNextCommand(err error, command string) error {
	return withNextCommandAndDocs(err, command, metadata.DocsRef("troubleshooting"))
}

// withNextCommandAndDocs is the internal variant that accepts a custom docs reference.
func withNextCommandAndDocs(err error, command, docsRef string) error {
	if err == nil || command == "" {
		return err
	}
	return fmt.Errorf("%w\nNext: %s\nMore info: %s", err, command, docsRef)
}

// EvaluateErrorWithHint is the primary hinting entry point for evaluation commands.
func EvaluateErrorWithHint(err error) error {
	if err == nil {
		return nil
	}

	hintData := SuggestForError(err)
	if hintData.NextCommand == "" {
		return err
	}

	return withNextCommandAndDocs(err, hintData.NextCommand, metadata.DocsRef(hintData.SearchQuery))
}

// SuggestForError resolves a remediation hint from an error.
func SuggestForError(err error) RemediationHint {
	if err == nil {
		return RemediationHint{}
	}

	if hint, ok := lookupHintBySentinel(err); ok {
		return hint
	}

	msg := strings.ToLower(err.Error())
	for _, entry := range hintRegistry {
		for _, p := range entry.patterns {
			if strings.Contains(msg, p) {
				return entry.hint
			}
		}
	}

	return RemediationHint{
		Reason:      "Unknown error encountered.",
		SearchQuery: buildSearchQueryFromError(err.Error()),
	}
}

func lookupHintBySentinel(err error) (RemediationHint, bool) {
	type unwrapMany interface {
		Unwrap() []error
	}

	queue := []error{err}
	seen := make(map[error]struct{})
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}
		if _, ok := seen[current]; ok {
			continue
		}
		seen[current] = struct{}{}

		if hint, ok := sentinelToHint[current]; ok {
			return hint, true
		}
		if many, ok := current.(unwrapMany); ok {
			queue = append(queue, many.Unwrap()...)
			continue
		}
		if next := errors.Unwrap(current); next != nil {
			queue = append(queue, next)
		}
	}
	return RemediationHint{}, false
}

func buildSearchQueryFromError(message string) string {
	clean := nonQueryToken.ReplaceAllString(strings.ToLower(message), " ")
	fields := strings.Fields(clean)
	if len(fields) == 0 {
		return "troubleshooting"
	}
	if len(fields) > 5 {
		fields = fields[:5]
	}
	return strings.Join(fields, " ")
}
