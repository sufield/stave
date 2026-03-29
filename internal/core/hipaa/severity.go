// Package control defines the interface and registry for programmatic
// safety controls evaluated against observation snapshots.
package hipaa

import "fmt"

// Severity classifies the impact level of an control violation.
// Ordering: CRITICAL > HIGH > MEDIUM > LOW.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var severityRank = map[Severity]int{
	Critical: 4,
	High:     3,
	Medium:   2,
	Low:      1,
}

// Rank returns the numeric rank of the severity (4=CRITICAL, 1=LOW, 0=unknown).
func (s Severity) Rank() int {
	return severityRank[s]
}

// Less reports whether s is strictly less severe than other.
func (s Severity) Less(other Severity) bool {
	return s.Rank() < other.Rank()
}

// IsValid reports whether s is one of the four defined severity levels.
func (s Severity) IsValid() bool {
	return s.Rank() > 0
}

// String returns the severity label.
func (s Severity) String() string {
	return string(s)
}

// ParseSeverity parses a case-insensitive severity string.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(s) {
	case Critical:
		return Critical, nil
	case High:
		return High, nil
	case Medium:
		return Medium, nil
	case Low:
		return Low, nil
	}
	return "", fmt.Errorf("unknown severity %q", s)
}
