package fix

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

var (
	fixInputPath  string
	fixFindingRef string
)

func runFix(cmd *cobra.Command, _ []string) error {
	inputPath := fsutil.CleanUserPath(fixInputPath)
	findings, err := loadFixFindings(inputPath)
	if err != nil {
		return err
	}
	needle, err := normalizedFixFindingRef()
	if err != nil {
		return err
	}
	selected, err := selectFixFinding(findings, needle)
	if err != nil {
		return err
	}
	selected = withRemediationPlan(selected)
	return writeFixResult(cmd.OutOrStdout(), selected)
}

func loadFixFindings(inputPath string) ([]remediation.Finding, error) {
	data, err := fsutil.ReadFileLimited(inputPath)
	if err != nil {
		return nil, fmt.Errorf("read --input: %w", err)
	}
	findings, err := parseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parse evaluation: %w", err)
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings in %s", inputPath)
	}
	return findings, nil
}

func normalizedFixFindingRef() (string, error) {
	needle := strings.TrimSpace(fixFindingRef)
	if needle == "" {
		return "", fmt.Errorf("--finding cannot be empty")
	}
	return needle, nil
}

func selectFixFinding(findings []remediation.Finding, needle string) (remediation.Finding, error) {
	for i := range findings {
		if fixFindingKey(findings[i]) == needle {
			return findings[i], nil
		}
	}
	keys := availableFindingKeys(findings)
	return remediation.Finding{}, fmt.Errorf(
		"finding %q not found; available finding IDs:\n%s",
		needle,
		strings.Join(keys, "\n"),
	)
}

func availableFindingKeys(findings []remediation.Finding) []string {
	keys := make([]string, 0, len(findings))
	for i := range findings {
		keys = append(keys, fixFindingKey(findings[i]))
	}
	slices.Sort(keys)
	return keys
}

func withRemediationPlan(selected remediation.Finding) remediation.Finding {
	if selected.RemediationPlan != nil {
		return selected
	}
	selected.RemediationPlan = remediation.NewPlanner().PlanFor(selected)
	return selected
}

func writeFixResult(w io.Writer, selected remediation.Finding) error {
	if _, err := fmt.Fprintf(w, "Finding: %s\n", fixFindingKey(selected)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Control: %s\n", selected.ControlName); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Asset: %s (%s)\n", selected.AssetID, selected.AssetType); err != nil {
		return err
	}
	remediationAction := strings.TrimSpace(selected.RemediationSpec.Action)
	if remediationAction != "" {
		if _, err := fmt.Fprintf(w, "Remediation: %s\n", remediationAction); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(w, "Fix Plan:"); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(selected.RemediationPlan)
}

func fixFindingKey(f remediation.Finding) string {
	return fmt.Sprintf("%s@%s", f.ControlID, f.AssetID)
}

func parseFindings(raw []byte) ([]remediation.Finding, error) {
	var env safetyenvelope.Evaluation
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Findings) > 0 {
		return env.Findings, nil
	}

	var wrapped struct {
		OK   bool                      `json:"ok"`
		Data safetyenvelope.Evaluation `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Data.Findings) > 0 {
		return wrapped.Data.Findings, nil
	}

	var direct struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct.Findings, nil
	}

	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("input JSON does not contain evaluation findings")
}
