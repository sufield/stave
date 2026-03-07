package json

import (
	"context"
	"strings"
	"testing"
)

func FuzzLoadSnapshotFromReader(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`[]`,
		`{`,
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","vendor":"aws","properties":{}}]}`,
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[]}`,
		`{"schema_version":"obs.v0.1"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	loader := NewObservationLoader()

	f.Fuzz(func(t *testing.T, input string) {
		loader.LoadSnapshotFromReader(context.Background(), strings.NewReader(input), "fuzz")
	})
}
