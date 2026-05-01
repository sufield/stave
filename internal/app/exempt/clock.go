package exempt

import (
	"time"

	"github.com/sufield/stave/internal/core/ports"
)

// NewTimestamp returns clk's current time formatted as an RFC3339 string
// in UTC. Centralizes the format used by every audit trail entry so the
// "what timestamp do we use" decision lives in one place. Pass
// ports.RealClock{} from production callers; tests substitute a
// FixedClock for deterministic output.
func NewTimestamp(clk ports.Clock) string {
	return clk.Now().UTC().Format(time.RFC3339)
}
