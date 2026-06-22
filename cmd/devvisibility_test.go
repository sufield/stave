package cmd

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
)

func TestApplyDevVisibility(t *testing.T) {
	newTree := func() (root, prod, dev, devSub *cobra.Command) {
		root = &cobra.Command{Use: "root"}
		prod = &cobra.Command{Use: "apply"}
		dev = &cobra.Command{Use: "forge", Annotations: map[string]string{cmdutil.AnnotationDevOnly: "true"}}
		devSub = &cobra.Command{Use: "new"}
		dev.AddCommand(devSub)
		root.AddCommand(prod, dev)
		return
	}

	// Default (showDev=false): dev-only hidden, production visible; restored after.
	root, prod, dev, _ := newTree()
	restore := applyDevVisibility(root, false)
	if !dev.Hidden {
		t.Fatal("default listing must hide the dev-only command")
	}
	if prod.Hidden {
		t.Fatal("default listing must keep the production command visible")
	}
	restore()
	if dev.Hidden {
		t.Fatal("restore must unhide the dev-only command")
	}

	// --show-dev (showDev=true): inverts — dev-only shown, production hidden.
	root, prod, dev, _ = newTree()
	restore = applyDevVisibility(root, true)
	if dev.Hidden {
		t.Fatal("--show-dev must show the dev-only command")
	}
	if !prod.Hidden {
		t.Fatal("--show-dev must hide the production command")
	}
	restore()
	if prod.Hidden {
		t.Fatal("restore must unhide the production command")
	}

	// Helping a dev-only command itself must not hide its own subtree.
	_, _, dev, devSub := newTree()
	applyDevVisibility(dev, false)()
	if devSub.Hidden {
		t.Fatal("subcommands of a dev-only command must stay visible in its own --help")
	}
}
