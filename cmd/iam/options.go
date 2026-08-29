package iam

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
)

type loopOptions struct {
	PolicyPath string
	Format     string
}

func addLoopFlags(cmd *cobra.Command, o *loopOptions) {
	cmd.Flags().StringVarP(&o.Format, "format", "f", "text", "output format: text, json")
}

func (o *loopOptions) Prepare(_ *cobra.Command) error {
	o.PolicyPath = fsutil.CleanUserPath(o.PolicyPath)

	if _, err := NewRenderer(o.Format); err != nil {
		return err
	}
	return nil
}
