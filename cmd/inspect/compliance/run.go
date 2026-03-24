package compliance

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	comp "github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func run(cmd *cobra.Command, file string, frameworks, checkIDs []string) error {
	raw, err := readInput(file, cmd.InOrStdin())
	if err != nil {
		return err
	}

	// Exercise ParseFramework for each requested framework.
	for _, f := range frameworks {
		if _, parseErr := comp.ParseFramework(f); parseErr != nil {
			return fmt.Errorf("invalid framework: %w", parseErr)
		}
	}

	// If no check IDs supplied, extract them from the YAML.
	if len(checkIDs) == 0 {
		checkIDs, err = extractCheckIDs(raw)
		if err != nil {
			return err
		}
	}

	resolution, err := comp.ResolveControlCrosswalk(raw, frameworks, checkIDs, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("resolve crosswalk: %w", err)
	}

	// Write the pre-formatted JSON directly.
	_, err = cmd.OutOrStdout().Write(resolution.ResolutionJSON)
	return err
}

func extractCheckIDs(raw []byte) ([]string, error) {
	// Minimal YAML parse to extract check IDs — only need top-level keys.
	// The full parse happens inside ResolveControlCrosswalk.
	type minimalCrosswalk struct {
		Checks map[string]any `yaml:"checks" json:"checks"`
	}

	// Try JSON first (some users may pass pre-converted JSON).
	var mc minimalCrosswalk
	if err := json.Unmarshal(raw, &mc); err == nil && len(mc.Checks) > 0 {
		ids := make([]string, 0, len(mc.Checks))
		for id := range mc.Checks {
			ids = append(ids, id)
		}
		return ids, nil
	}

	// For YAML, pass through with all keys — ResolveControlCrosswalk handles
	// the actual parsing. Return nil to let it process all checks.
	return nil, nil
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file == "" {
		return io.ReadAll(stdin)
	}
	data, err := fsutil.ReadFileLimited(file)
	if err != nil {
		return nil, fmt.Errorf("read crosswalk file: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("crosswalk file is empty")
	}
	return data, nil
}
