// Package exception implements the acknowledged exception mechanism for
// controls that have legitimate configurations failing checks. Exceptions
// require compensating controls that must all pass for the exception to
// be valid.
package exception

import (
	"fmt"
	"os"
	"strings"

	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/profile"

	"gopkg.in/yaml.v3"
)

// ExceptionConfig represents a single acknowledged exception declaration.
type ExceptionConfig struct {
	ControlID        string   `yaml:"control_id" json:"control_id"`
	Bucket           string   `yaml:"bucket" json:"bucket"`
	Rationale        string   `yaml:"rationale" json:"rationale"`
	AcknowledgedBy   string   `yaml:"acknowledged_by" json:"acknowledged_by"`
	AcknowledgedDate string   `yaml:"acknowledged_date" json:"acknowledged_date"`
	RequiresPassing  []string `yaml:"requires_passing" json:"requires_passing"`
}

// StaveConfig is the top-level stave.yaml structure (only exceptions parsed).
type StaveConfig struct {
	Exceptions []ExceptionConfig `yaml:"exceptions"`
}

// LoadExceptions loads exception declarations from a stave.yaml file.
// Returns nil with no error if the file does not exist.
func LoadExceptions(path string) ([]ExceptionConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from user config
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg StaveConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	for i, exc := range cfg.Exceptions {
		if err := validateException(exc); err != nil {
			return nil, fmt.Errorf("exception[%d] (%s): %w", i, exc.ControlID, err)
		}
	}

	return cfg.Exceptions, nil
}

func validateException(exc ExceptionConfig) error {
	if strings.TrimSpace(exc.ControlID) == "" {
		return fmt.Errorf("control_id is required")
	}
	if strings.TrimSpace(exc.Rationale) == "" {
		return fmt.Errorf("rationale is required")
	}
	if len(exc.RequiresPassing) == 0 {
		return fmt.Errorf("requires_passing is mandatory — compensating controls must be specified")
	}
	return nil
}

// AcknowledgedResult represents the outcome of applying an exception.
type AcknowledgedResult struct {
	ControlID            string                `json:"control_id"`
	Bucket               string                `json:"bucket"`
	Rationale            string                `json:"rationale"`
	AcknowledgedBy       string                `json:"acknowledged_by"`
	AcknowledgedDate     string                `json:"acknowledged_date"`
	CompensatingControls []CompensatingControl `json:"compensating_controls"`
	Valid                bool                  `json:"valid"`
	InvalidReason        string                `json:"invalid_reason,omitempty"`
}

// CompensatingControl shows the status of a required compensating invariant.
type CompensatingControl struct {
	ControlID string `json:"control_id"`
	Passing   bool   `json:"passing"`
}

// ApplyExceptions processes exception declarations against profile results.
// It modifies results in place: valid exceptions change FAIL to ACKNOWLEDGED.
// Returns the list of acknowledged results for reporting.
func ApplyExceptions(exceptions []ExceptionConfig, results []profile.ProfileResult) []AcknowledgedResult {
	if len(exceptions) == 0 {
		return nil
	}

	// Build result lookup.
	resultMap := make(map[string]*profile.ProfileResult)
	for i := range results {
		resultMap[results[i].ControlID] = &results[i]
	}

	var acknowledged []AcknowledgedResult

	for _, exc := range exceptions {
		r, exists := resultMap[exc.ControlID]
		if !exists || r.Pass {
			continue // not evaluated or already passing
		}

		// Check compensating controls.
		controls := make([]CompensatingControl, len(exc.RequiresPassing))
		allPassing := true
		for i, reqID := range exc.RequiresPassing {
			passing := false
			if req, ok := resultMap[reqID]; ok {
				passing = req.Pass
			}
			controls[i] = CompensatingControl{ControlID: reqID, Passing: passing}
			if !passing {
				allPassing = false
			}
		}

		ack := AcknowledgedResult{
			ControlID:            exc.ControlID,
			Bucket:               exc.Bucket,
			Rationale:            exc.Rationale,
			AcknowledgedBy:       exc.AcknowledgedBy,
			AcknowledgedDate:     exc.AcknowledgedDate,
			CompensatingControls: controls,
			Valid:                allPassing,
		}

		if allPassing {
			// Exception is valid: change result to ACKNOWLEDGED.
			r.Finding = fmt.Sprintf("ACKNOWLEDGED: %s (exception by %s on %s)",
				exc.Rationale, exc.AcknowledgedBy, exc.AcknowledgedDate)
			r.Remediation = ""
			r.Pass = true
			r.Severity = compliance.Low
		} else {
			// Exception invalid: keep FAIL, note the failure.
			var failing []string
			for _, c := range controls {
				if !c.Passing {
					failing = append(failing, c.ControlID)
				}
			}
			ack.InvalidReason = fmt.Sprintf("compensating control(s) not passing: %s",
				strings.Join(failing, ", "))
			r.Finding = r.Finding + fmt.Sprintf(
				" [Exception declared but compensating control %s is not passing]",
				strings.Join(failing, ", "))
		}

		acknowledged = append(acknowledged, ack)
	}

	return acknowledged
}
