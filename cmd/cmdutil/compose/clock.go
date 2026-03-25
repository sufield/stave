package compose

import (
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// ResolveClock returns a FixedClock if a timestamp is provided, otherwise RealClock.
func ResolveClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := cmdutil.ParseRFC3339(raw, "--now")
	if err != nil {
		return nil, err
	}
	return ports.FixedClock(t), nil
}
