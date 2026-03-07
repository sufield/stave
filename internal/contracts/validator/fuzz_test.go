package validator

import "testing"

func FuzzValidateObservationJSON(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`[]`,
		`{`,
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[]}`,
		`{"schema_version":"obs.v0.1","captured_at":"2026-01-01T00:00:00Z","assets":[{"id":"r-1","type":"storage_bucket","vendor":"aws","properties":{}}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	v := New()

	f.Fuzz(func(t *testing.T, data []byte) {
		v.ValidateObservationJSON(data)
	})
}

func FuzzValidateControlYAML(f *testing.F) {
	seeds := []string{
		``,
		`{}`,
		`dsl_version: ctrl.v1
id: CTL.TEST.001
description: test
severity: high
source_type: storage_bucket
unsafe_predicate:
  all:
    - field: public
      op: eq
      value: true`,
		`not valid yaml: [`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	v := New()

	f.Fuzz(func(t *testing.T, data []byte) {
		v.ValidateControlYAML(data)
	})
}
