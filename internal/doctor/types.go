package doctor

import "fmt"

// Status represents the health level of a diagnostic check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// Check represents the result of an environmental or system diagnostic.
type Check struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// IsFail reports whether the check represents a system failure.
func (c Check) IsFail() bool {
	return c.Status == StatusFail
}

// String implements fmt.Stringer for easy logging of check results.
func (c Check) String() string {
	return fmt.Sprintf("[%s] %s: %s", c.Status, c.Name, c.Message)
}

// Context encapsulates the system and environment data required to run diagnostics.
type Context struct {
	Cwd          string
	BinaryPath   string
	Goos         string
	Goarch       string
	GoVersion    string
	StaveVersion string

	// Dependencies (injectable for testing)
	LookPathFn func(file string) (string, error)
	GetenvFn   func(key string) string
}

// CheckFunc is the signature for an individual diagnostic probe.
type CheckFunc func(ctx *Context) Check
