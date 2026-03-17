package compose

import (
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// ResolveClock returns a FixedClock if a timestamp is provided, otherwise RealClock.
func ResolveClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := timeutil.ParseRFC3339(raw, "--now")
	if err != nil {
		return nil, err
	}
	return ports.FixedClock(t), nil
}
