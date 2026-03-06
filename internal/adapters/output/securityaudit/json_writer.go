package securityaudit

import (
	"encoding/json"
	"fmt"

	domain "github.com/sufield/stave/internal/domain/securityaudit"
)

// MarshalJSONReport renders the security-audit report as indented JSON.
func MarshalJSONReport(report domain.Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal security audit json: %w", err)
	}
	return append(data, '\n'), nil
}
