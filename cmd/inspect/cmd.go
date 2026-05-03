package inspect

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/inspect/acl"
	"github.com/sufield/stave/cmd/inspect/aliases"
	"github.com/sufield/stave/cmd/inspect/compliance"
	"github.com/sufield/stave/cmd/inspect/exposure"
	"github.com/sufield/stave/cmd/inspect/policy"
	"github.com/sufield/stave/cmd/inspect/risk"
	"github.com/sufield/stave/internal/platform/metadata"
)

// NewInspectCmd constructs the inspect command tree. The S3 resolver
// arrives via the injected factory so test code (and future
// non-AWS deployments) can substitute alternatives without touching
// the cobra wiring.
func NewInspectCmd(newS3Resolver compose.S3ResolverFactory) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Low-level security analysis primitives",
		Long: `Inspect provides direct access to Stave's domain analysis engines.

Each subcommand reads JSON from --file or stdin and outputs analysis results
as JSON. These are building blocks for custom tooling and debugging.

Subcommands:
  policy      S3 bucket policy analysis
  acl         S3 ACL grant analysis
  exposure    Exposure classification
  risk        Risk scoring
  compliance  Framework crosswalk
  aliases     Predicate alias listing` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	resolver := newS3Resolver()
	cmd.AddCommand(policy.NewCmd(resolver))
	cmd.AddCommand(acl.NewCmd())
	cmd.AddCommand(exposure.NewCmd())
	cmd.AddCommand(risk.NewCmd(resolver))
	cmd.AddCommand(compliance.NewCmd())
	cmd.AddCommand(aliases.NewCmd())

	return cmd
}
