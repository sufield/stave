package forgecmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// fixtureFile / fixtureResource are the minimal fixture JSON shape shared by
// Scaffold (writer) and Test (reader).
type fixtureFile struct {
	Resources []fixtureResource `json:"resources"`
}

type fixtureResource struct {
	AssetID    string         `json:"asset_id"`
	Properties map[string]any `json:"properties"`
}

// Test evaluates a control against pass/fail fixtures (and optionally a real
// snapshot) and returns the assertion report. When any assertion fails it also
// returns a non-nil gating error (the command maps it to exit 4; the report is
// still rendered). It is the library entry point behind `stave forge test`.
// The report's trailing "Nms" is the wall-clock run time (inherently variable).
func Test(controlPath, passFixture, failFixture, snapshotPath string, verbose bool) ([]byte, error) {
	start := time.Now()

	data, err := os.ReadFile(fsutil.CleanUserPath(controlPath)) //nolint:gosec // user path
	if err != nil {
		return nil, fmt.Errorf("read control: %w", err)
	}
	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		return nil, fmt.Errorf("parse control: %w", err)
	}
	if prepErr := ctl.Prepare(); prepErr != nil {
		return nil, fmt.Errorf("prepare control: %w", prepErr)
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, fmt.Errorf("init CEL: %w", err)
	}

	var buf bytes.Buffer
	passed := 0
	failed := 0

	if passFixture != "" {
		assets, loadErr := loadFixture(passFixture)
		if loadErr != nil {
			return nil, fmt.Errorf("load pass fixture: %w", loadErr)
		}
		for _, a := range assets {
			unsafe, evalErr := celEval(ctl, a, nil)
			if evalErr != nil {
				fmt.Fprintf(&buf, "X %s -- pass fixture: ERROR  %v\n", ctl.ID, evalErr)
				failed++
				continue
			}
			if unsafe {
				fmt.Fprintf(&buf, "X %s -- pass fixture: FAIL (got verdict=fail, expected pass)\n", ctl.ID)
				writeTrace(&buf, a)
				failed++
			} else {
				fmt.Fprintf(&buf, "  %s -- pass fixture: PASS (verdict=pass as expected)\n", ctl.ID)
				passed++
			}
		}
	}

	if failFixture != "" {
		assets, loadErr := loadFixture(failFixture)
		if loadErr != nil {
			return nil, fmt.Errorf("load fail fixture: %w", loadErr)
		}
		for _, a := range assets {
			unsafe, evalErr := celEval(ctl, a, nil)
			if evalErr != nil {
				fmt.Fprintf(&buf, "X %s -- fail fixture: ERROR  %v\n", ctl.ID, evalErr)
				failed++
				continue
			}
			if !unsafe {
				fmt.Fprintf(&buf, "X %s -- fail fixture: FAIL (got verdict=pass, expected fail)\n", ctl.ID)
				writeTrace(&buf, a)
				failed++
			} else {
				fmt.Fprintf(&buf, "  %s -- fail fixture: PASS (verdict=fail as expected)\n", ctl.ID)
				passed++
			}
		}
	}

	if snapshotPath != "" {
		snaps, loadErr := observations.LoadBundle(snapshotPath)
		if loadErr != nil {
			return nil, fmt.Errorf("load snapshot: %w", loadErr)
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
					fmt.Fprintf(&buf, "  %s -- snapshot: %s  %s\n", ctl.ID, verdict, snap.Assets[i].ID)
				}
			}
			fmt.Fprintf(&buf, "  %s -- snapshot: evaluated %d assets\n", ctl.ID, matchCount)
			passed++
		}
	}

	elapsed := time.Since(start)
	total := passed + failed
	fmt.Fprintf(&buf, "\n%d/%d assertions passed in %dms\n", passed, total, elapsed.Milliseconds())

	if failed > 0 {
		return buf.Bytes(), fmt.Errorf("%d assertion(s) failed", failed)
	}
	return buf.Bytes(), nil
}

func loadFixture(path string) ([]asset.Asset, error) {
	data, err := os.ReadFile(fsutil.CleanUserPath(path)) //nolint:gosec // user path
	if err != nil {
		return nil, fmt.Errorf("read fixture %s: %w", path, err)
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
		data, err := json.MarshalIndent(a.Properties, "  ", "  ")
		if err != nil {
			fmt.Fprintf(w, "  Properties: <marshal failed: %v>\n", err)
			return
		}
		fmt.Fprintf(w, "  Properties: %s\n", data)
	}
}
