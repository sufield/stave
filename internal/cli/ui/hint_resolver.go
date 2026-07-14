package ui

import (
	"errors"
	"strings"

	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/internal/util/strutil"
)

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

	errMsg := err.Error()
	for _, entry := range hintRegistry {
		for _, p := range entry.patterns {
			if strutil.ContainsFold(errMsg, p) {
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
	var lowerMessage string
	needsLower := false
	for i := 0; i < len(message); i++ {
		if message[i] >= 'A' && message[i] <= 'Z' {
			needsLower = true
			break
		}
	}
	if needsLower {
		lowerMessage = strings.ToLower(message)
	} else {
		lowerMessage = message
	}
	clean := nonQueryToken.ReplaceAllString(lowerMessage, " ")
	fields := strings.Fields(clean)
	if len(fields) == 0 {
		return "troubleshooting"
	}
	if len(fields) > 5 {
		fields = fields[:5]
	}
	return strings.Join(fields, " ")
}

