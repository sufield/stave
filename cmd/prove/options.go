package prove

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var validQueries = []string{
	"compatibility",
	"reachability",
	"conflict",
	"choke-point",
	"invariant",
}

type options struct {
	observations    string
	controls        string
	query           string
	principal       string
	action          string
	resource        string
	invariantID     string
	format          string
	certificatePath string
	compliance      string
	historyDir      string
}

func addFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVarP(&o.observations, "observations", "o", "", "path to observations directory (required)")
	f.StringVar(&o.query, "query", "", "query to run: compatibility, reachability, conflict, choke-point, invariant (required)")
	f.StringVarP(&o.controls, "controls", "i", "", "control definitions directory (empty = built-in catalog)")
	f.StringVarP(&o.format, "format", "f", "json", "output format: json, text")
	f.StringVar(&o.principal, "principal", "", "principal ARN (compatibility, reachability, choke-point)")
	f.StringVar(&o.action, "action", "", "action (compatibility)")
	f.StringVar(&o.resource, "resource", "", "resource ARN (compatibility, reachability, choke-point)")
	f.StringVar(&o.invariantID, "invariant", "", "invariant control ID (invariant query)")
	f.StringVar(&o.certificatePath, "certificate", "", "write SMT-LIB proof certificate to this path")
	f.StringVar(&o.compliance, "compliance", "", "compliance frameworks to map (comma-separated, or 'all')")
	f.StringVar(&o.historyDir, "history", "", "append result to proof history in this directory")
	_ = cmd.MarkFlagRequired("observations")
	_ = cmd.MarkFlagRequired("query")
}

// Prepare validates flags at the CLI boundary.
func (o *options) Prepare(_ *cobra.Command) error {
	o.observations = fsutil.CleanUserPath(o.observations)

	if !isValidQuery(o.query) {
		return &ui.UserError{
			Err: fmt.Errorf("unknown --query %q (valid: compatibility, reachability, conflict, choke-point, invariant)", o.query),
		}
	}

	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}

	switch o.query {
	case "compatibility":
		if o.principal == "" || o.action == "" || o.resource == "" {
			return &ui.UserError{
				Err: errors.New("compatibility query requires --principal, --action, and --resource"),
			}
		}
	case "reachability", "choke-point":
		if o.principal == "" || o.resource == "" {
			return &ui.UserError{
				Err: fmt.Errorf("%s query requires --principal and --resource", o.query),
			}
		}
	case "invariant":
		if o.invariantID == "" {
			return &ui.UserError{
				Err: errors.New("invariant query requires --invariant"),
			}
		}
	}

	return nil
}

func isValidQuery(q string) bool {
	return slices.Contains(validQueries, q)
}
