package ui

import (
	"errors"
	"regexp"
	"strings"
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
			NextCommand: "stave init --profile aws-s3",
			SearchQuery: "init controls directory not accessible",
		},
	},
	{
		err:      ErrHintObservationsNotAccessible,
		patterns: []string{"--observations not accessible"},
		hint: RemediationHint{
			Reason:      "Observation snapshots are missing or unreadable.",
			NextCommand: "stave ingest --profile aws-s3 --input ./snapshots/raw/aws-s3 --out ./observations",
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
			NextCommand: "stave ingest --profile aws-s3 --input ./snapshots/raw/aws-s3 --out ./observations",
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
