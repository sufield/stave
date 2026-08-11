package prove

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

func run(cmd *cobra.Command, o *options) error {
	if o.query == "universal" {
		return runUniversal(cmd, o)
	}

	renderer, err := NewRenderer(o.format)
	if err != nil {
		return err
	}

	result, err := stave.Prove(cmd.Context(), stave.ProveConfig{
		SnapshotsDir:    o.observations,
		ControlsDir:     o.controls,
		Query:           o.query,
		Principal:       o.principal,
		Action:          o.action,
		Resource:        o.resource,
		InvariantID:     o.invariantID,
		CertificatePath: o.certificatePath,
	})
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped ("prove: ..."); preserve exit 4.
	}

	var complianceMap map[string][]ComplianceRequirement
	if o.compliance != "" {
		complianceMap, err = loadComplianceMapping(o.query, o.compliance)
		if err != nil {
			return fmt.Errorf("load compliance mapping: %w", err)
		}
	}

	if o.historyDir != "" {
		if err := appendHistory(o.historyDir, result, o.certificatePath); err != nil {
			return fmt.Errorf("append proof history: %w", err)
		}
	}

	output := &ProveOutput{
		Result:         result,
		Compliance:     complianceMap,
		CertificateRef: o.certificatePath,
	}

	if err := renderer.Render(cmd.OutOrStdout(), output); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// ProveOutput wraps the query result with compliance and certificate metadata.
type ProveOutput struct {
	Result         *stave.ProveResult
	Compliance     map[string][]ComplianceRequirement
	CertificateRef string
}

// ComplianceRequirement is one framework requirement satisfied by a proof.
type ComplianceRequirement struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description" yaml:"description"`
	Status      string `json:"status"`
}

// HistoryEntry is one proof run appended to the JSONL history.
type HistoryEntry struct {
	QueryName       string            `json:"query_name"`
	Timestamp       string            `json:"timestamp"`
	Result          string            `json:"result"`
	SolveTimeMs     int64             `json:"solve_time_ms"`
	Witness         map[string]string `json:"witness,omitempty"`
	CertificatePath string            `json:"certificate,omitempty"`
}

func appendHistory(dir string, result *stave.ProveResult, certPath string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	entry := HistoryEntry{
		QueryName:       result.QueryName,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Result:          result.Result,
		SolveTimeMs:     result.SolveTimeMs,
		Witness:         result.Witness,
		CertificatePath: certPath,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}
	data = append(data, '\n')

	historyFile := filepath.Clean(filepath.Join(dir, "history.jsonl"))
	f, err := os.OpenFile(historyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // path from user flag, cleaned above
	if err != nil {
		return fmt.Errorf("open history file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write history entry: %w", err)
	}
	return nil
}

func loadComplianceMapping(queryName, frameworks string) (map[string][]ComplianceRequirement, error) {
	mappings, err := LoadProofMappings()
	if err != nil {
		return nil, err
	}

	prop, ok := mappings.Properties[queryName]
	if !ok {
		return nil, nil
	}

	var requested []string
	if frameworks == "all" {
		for k := range prop.Mappings {
			requested = append(requested, k)
		}
	} else {
		requested = strings.Split(frameworks, ",")
	}

	result := make(map[string][]ComplianceRequirement)
	for _, fw := range requested {
		fw = strings.TrimSpace(fw)
		reqs, ok := prop.Mappings[fw]
		if !ok {
			continue
		}
		mapped := make([]ComplianceRequirement, len(reqs))
		for i, r := range reqs {
			mapped[i] = ComplianceRequirement{
				ID:          r.ID,
				Description: r.Description,
				Status:      "satisfied",
			}
		}
		result[fw] = mapped
	}
	return result, nil
}
