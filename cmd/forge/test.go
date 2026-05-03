package forge

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func newTestCmd() *cobra.Command {
	var controlPath, passFixture, failFixture, snapshotPath string
	var watch, verbose bool

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run fixture-based assertions against a control",
		Long: `Evaluate a control predicate against pass and fail fixture files
and assert the expected verdict. Shows predicate trace on failure.

Exit Codes:
  0   All assertions passed
  1   One or more assertions failed
  2   Invalid input
  4   Internal error`,
		Example: `  stave forge test \
    --control controls/ad/CTL.AD.PASS.MINLEN.001.yaml \
    --pass testdata/fixture-pass.json \
    --fail testdata/fixture-fail.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if passFixture == "" && failFixture == "" && snapshotPath == "" {
				return errors.New("at least one of --pass, --fail, or --snapshot is required")
			}
			return runForgeTest(cmd.OutOrStdout(), controlPath, passFixture, failFixture, snapshotPath, verbose)
		},
	}

	cmd.Flags().StringVar(&controlPath, "control", "", "path to control YAML file (required)")
	cmd.Flags().StringVar(&passFixture, "pass", "", "fixture that must produce verdict: pass")
	cmd.Flags().StringVar(&failFixture, "fail", "", "fixture that must produce verdict: fail")
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "real snapshot for smoke test")
	cmd.Flags().BoolVar(&watch, "watch", false, "re-run on control file change")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "show trace on pass")
	_ = cmd.MarkFlagRequired("control")

	return cmd
}

func runForgeTest(w io.Writer, controlPath, passFixture, failFixture, snapshotPath string, verbose bool) error {
	start := time.Now()

	// Load control.
	data, err := os.ReadFile(fsutil.CleanUserPath(controlPath)) //nolint:gosec // user path
	if err != nil {
		return fmt.Errorf("read control: %w", err)
	}
	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		return fmt.Errorf("parse control: %w", err)
	}
	if prepErr := ctl.Prepare(); prepErr != nil {
		return fmt.Errorf("prepare control: %w", prepErr)
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return fmt.Errorf("init CEL: %w", err)
	}

	passed := 0
	failed := 0

	// Test pass fixture.
	if passFixture != "" {
		assets, loadErr := loadFixture(passFixture)
		if loadErr != nil {
			return fmt.Errorf("load pass fixture: %w", loadErr)
		}
		for _, a := range assets {
			unsafe, evalErr := celEval(ctl, a, nil)
			if evalErr != nil {
				fmt.Fprintf(w, "X %s -- pass fixture: ERROR  %v\n", ctl.ID, evalErr)
				failed++
				continue
			}
			if unsafe {
				fmt.Fprintf(w, "X %s -- pass fixture: FAIL (got verdict=fail, expected pass)\n", ctl.ID)
				writeTrace(w, a)
				failed++
			} else {
				fmt.Fprintf(w, "  %s -- pass fixture: PASS (verdict=pass as expected)\n", ctl.ID)
				passed++
			}
		}
	}

	// Test fail fixture.
	if failFixture != "" {
		assets, loadErr := loadFixture(failFixture)
		if loadErr != nil {
			return fmt.Errorf("load fail fixture: %w", loadErr)
		}
		for _, a := range assets {
			unsafe, evalErr := celEval(ctl, a, nil)
			if evalErr != nil {
				fmt.Fprintf(w, "X %s -- fail fixture: ERROR  %v\n", ctl.ID, evalErr)
				failed++
				continue
			}
			if !unsafe {
				fmt.Fprintf(w, "X %s -- fail fixture: FAIL (got verdict=pass, expected fail)\n", ctl.ID)
				writeTrace(w, a)
				failed++
			} else {
				fmt.Fprintf(w, "  %s -- fail fixture: PASS (verdict=fail as expected)\n", ctl.ID)
				passed++
			}
		}
	}

	// Smoke test against real snapshot.
	if snapshotPath != "" {
		snaps, loadErr := observations.LoadBundle(snapshotPath)
		if loadErr != nil {
			return fmt.Errorf("load snapshot: %w", loadErr)
		}
		if len(snaps) > 0 {
			snap := snaps[len(snaps)-1]
			matchCount := 0
			for i := range snap.Assets {
				unsafe, evalErr := celEval(ctl, snap.Assets[i], nil)
				if evalErr != nil {
					continue
				}
				matchCount++
				verdict := "pass"
				if unsafe {
					verdict = "fail"
				}
				if verbose {
					fmt.Fprintf(w, "  %s -- snapshot: %s  %s\n", ctl.ID, verdict, snap.Assets[i].ID)
				}
			}
			fmt.Fprintf(w, "  %s -- snapshot: evaluated %d assets\n", ctl.ID, matchCount)
			passed++
		}
	}

	elapsed := time.Since(start)
	total := passed + failed
	fmt.Fprintf(w, "\n%d/%d assertions passed in %dms\n", passed, total, elapsed.Milliseconds())

	if failed > 0 {
		return fmt.Errorf("%d assertion(s) failed", failed)
	}
	return nil
}

// loadFixture loads a minimal fixture JSON file.
type fixtureFile struct {
	Resources []fixtureResource `json:"resources"`
}

type fixtureResource struct {
	AssetID    string         `json:"asset_id"`
	Properties map[string]any `json:"properties"`
}

func loadFixture(path string) ([]asset.Asset, error) {
	data, err := os.ReadFile(fsutil.CleanUserPath(path)) //nolint:gosec // user path
	if err != nil {
		return nil, err
	}

	var f fixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	var assets []asset.Asset
	for _, r := range f.Resources {
		assets = append(assets, asset.Asset{
			ID:         asset.ID(r.AssetID),
			Properties: r.Properties,
		})
	}
	return assets, nil
}

func writeTrace(w io.Writer, a asset.Asset) {
	fmt.Fprintf(w, "  Fixture asset: %s\n", a.ID)
	if len(a.Properties) > 0 {
		data, _ := json.MarshalIndent(a.Properties, "  ", "  ")
		fmt.Fprintf(w, "  Properties: %s\n", data)
	}
}
