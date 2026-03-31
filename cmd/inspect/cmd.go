package inspect

import (
	"github.com/spf13/cobra"

	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"

	"github.com/sufield/stave/cmd/inspect/acl"
	"github.com/sufield/stave/cmd/inspect/aliases"
	"github.com/sufield/stave/cmd/inspect/compliance"
	"github.com/sufield/stave/cmd/inspect/exposure"
	"github.com/sufield/stave/cmd/inspect/policy"
	"github.com/sufield/stave/cmd/inspect/risk"
	"github.com/sufield/stave/internal/metadata"
)

// NewInspectCmd constructs the inspect command tree.
func NewInspectCmd() *cobra.Command {
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

	resolver := s3resolver.NewResolver()
	cmd.AddCommand(policy.NewCmd(resolver))
	cmd.AddCommand(acl.NewCmd())
	cmd.AddCommand(exposure.NewCmd())
	cmd.AddCommand(risk.NewCmd(resolver))
	cmd.AddCommand(compliance.NewCmd())
	cmd.AddCommand(aliases.NewCmd())

	return cmd
}
