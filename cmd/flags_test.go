package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestAddGlobalFlags_LogFormatDefault locks the bookkeeping invariant
// the Value.Set + DefValue/Changed mutation in AddGlobalFlags is meant
// to preserve: the log-format flag must look "not user-supplied" to
// resolveGlobalFlagDefaults so a config-file override can take effect.
//
// If pflag ever exposes a SetDefault hook on Value-typed flags, the
// mutation path can be replaced wholesale; this test will keep the
// observable contract steady through that swap.
func TestAddGlobalFlags_LogFormatDefault(t *testing.T) {
	t.Parallel()
	root := &cobra.Command{Use: "stave-test"}
	flags := &globalFlagsType{}
	AddGlobalFlags(root, flags)

	f := root.PersistentFlags().Lookup("log-format")
	if f == nil {
		t.Fatal("log-format flag not registered")
	}
	if f.Changed {
		t.Errorf("log-format Changed=true after seeding default; expected false (user did not pass --log-format)")
	}
	if f.DefValue != "text" {
		t.Errorf("log-format DefValue=%q; want %q", f.DefValue, "text")
	}
	if got := f.Value.String(); got != "text" {
		t.Errorf("log-format Value=%q; want %q", got, "text")
	}
}
