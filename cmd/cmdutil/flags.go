package cmdutil

// HistoryOptions captures the canonical flags used by commands that
// read a directory of previous assessment artifacts plus an SLA policy
// profile (cmd/apply, cmd/budget, cmd/score, cmd/consolidate,
// cmd/trend/forecast, etc.).
type HistoryOptions struct {
	HistoryDir string
	SLAProfile string
}
