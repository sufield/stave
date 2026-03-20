package engine

import "time"

const defaultRunnerMaxGapThreshold = 12 * time.Hour

func (e *Runner) maxGapThreshold() time.Duration {
	if e.MaxGapThreshold > 0 {
		return e.MaxGapThreshold
	}
	return defaultRunnerMaxGapThreshold
}
