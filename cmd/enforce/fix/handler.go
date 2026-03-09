package fix

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	evaljson "github.com/sufield/stave/internal/adapters/input/evaluation/json"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type fixFlagsType struct {
	inputPath  string
	findingRef string
}

func runFix(cmd *cobra.Command, flags *fixFlagsType) error {
	inputPath := fsutil.CleanUserPath(flags.inputPath)
	findings, err := loadFixFindings(inputPath)
	if err != nil {
		return err
	}
	needle := strings.TrimSpace(flags.findingRef)
	if needle == "" {
		return fmt.Errorf("--finding cannot be empty")
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
	findings, err := evaljson.ParseFindings(data)
	if err != nil {
		return nil, fmt.Errorf("parse evaluation: %w", err)
	}
	if len(findings) == 0 {
		return nil, fmt.Errorf("no findings in %s", inputPath)
	}
	return findings, nil
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
