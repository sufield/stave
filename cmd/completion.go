package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for stave.

To install completions:

  # Bash (add to ~/.bashrc)
  source <(stave completion bash)

  # Zsh (add to ~/.zshrc)
  source <(stave completion zsh)

  # Fish
  stave completion fish | source

  # PowerShell
  stave completion powershell | Out-String | Invoke-Expression

Exit Codes:
  0   Success
  2   Invalid argument (unsupported shell)`,
		Example: `  stave completion bash
  stave completion zsh >> ~/.zshrc
  stave completion fish | source`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		SilenceUsage:          true,
		SilenceErrors:         true,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(os.Stdout, true)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
	return cmd
}
