package kernel

import "errors"

// ErrEmptyDuration is returned when an empty string is passed to ParseDuration.
var ErrEmptyDuration = errors.New("empty duration")
