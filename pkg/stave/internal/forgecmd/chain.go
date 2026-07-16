package forgecmd

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/app/chainforge"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ChainLint validates a chain definition (member control IDs exist in the
// catalog, capability strings valid, escalation threshold correct) and returns
// the report. When errors exist it also returns a non-nil gating error (the
// command maps it to exit 4; the report is still rendered). It is the library
// entry point behind `stave forge chain lint`.
func ChainLint(chainPath, controlsDir string) ([]byte, error) {
	data, err := fsutil.ReadFileLimited(chainPath)
	if err != nil {
		return nil, fmt.Errorf("read chain: %w", err)
	}

	var chain policy.ChainDefinition
	if unmarshalErr := yaml.Unmarshal(data, &chain); unmarshalErr != nil {
		return nil, fmt.Errorf("parse chain YAML: %w", unmarshalErr)
	}

	controlIDs := loadControlIDs(controlsDir)

	result := chainforge.LintChainRaw(data, &chain, controlIDs, capabilities.Builtin())

	var buf bytes.Buffer
	_, _ = fmt.Fprint(&buf, chainforge.FormatLint(result))
	fmt.Fprintf(&buf, "\n%d error(s), %d warning(s)\n", len(result.Errors), len(result.Warnings))

	if len(result.Errors) > 0 {
		return buf.Bytes(), fmt.Errorf("%d chain lint error(s)", len(result.Errors))
	}
	return buf.Bytes(), nil
}

func loadControlIDs(dir string) map[kernel.ControlID]struct{} {
	chains, err := ctlyaml.LoadChains(dir, capabilities.Builtin())
	_ = chains // we want control IDs, not chain IDs
	if err != nil {
		return nil
	}

	paths, walkErr := collectControlPaths(dir)
	if walkErr != nil {
		return nil
	}

	ids := make(map[kernel.ControlID]struct{}, len(paths))
	for _, p := range paths {
		data, readErr := os.ReadFile(fsutil.CleanUserPath(p))
		if readErr != nil {
			continue
		}
		ctl, unmarshalErr := ctlyaml.UnmarshalControlDefinition(data)
		if unmarshalErr != nil {
			continue
		}
		ids[ctl.ID] = struct{}{}
	}
	return ids
}
