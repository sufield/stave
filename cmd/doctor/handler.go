package doctor

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/doctor"
	staveversion "github.com/sufield/stave/internal/version"
)

func runDoctor(cmd *cobra.Command, _ []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve current directory: %w", err)
	}

	binaryPath, _ := os.Executable()

	checks, hasFail := doctor.Run(doctor.Context{
		Cwd:          cwd,
		BinaryPath:   binaryPath,
		StaveVersion: staveversion.Version,
	})

	format, err := cmdutil.ResolveFormatValue(cmd, doctorFormat)
	if err != nil {
		return err
	}

	if cmdutil.QuietEnabled(cmd) {
		if hasFail {
			return fmt.Errorf("doctor found required issues")
		}
		return nil
	}

	if format.IsJSON() {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Ready  bool           `json:"ready"`
			Checks []doctor.Check `json:"checks"`
		}{
			Ready:  !hasFail,
			Checks: checks,
		})
	}

	for _, c := range checks {
		fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s: %s\n", c.Status, c.Name, c.Message)
		if c.Fix != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "      Fix: %s\n", c.Fix)
		}
	}

	if hasFail {
		return fmt.Errorf("doctor found required issues")
	}
	return nil
}
