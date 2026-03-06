package doctor

// Status represents diagnostic health result levels.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Check is an environment/system diagnostic check result.
type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// Context provides environment data for running checks.
type Context struct {
	Cwd          string
	BinaryPath   string
	LookPathFn   func(file string) (string, error)
	GetenvFn     func(key string) string
	Goos         string
	Goarch       string
	GoVersion    string
	StaveVersion string
}

// CheckFunc is a function that produces a single Check result.
type CheckFunc func(ctx Context) Check
