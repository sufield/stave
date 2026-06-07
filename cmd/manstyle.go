package cmd

// Man-page-style help, adapted from the contributed manstyle.go to the repo's
// own CLI infrastructure instead of pulling in golang.org/x/term and a second
// pager:
//   - TTY/color decisions go through internal/cli/ui (IsTerminal / CanColor —
//     the same gate that honors NO_COLOR, --no-color, and TERM=dumb), not
//     golang.org/x/term (which the project deliberately does not depend on).
//   - `--help` is paged through ui.NewPager — the SAME TTY-aware pager the
//     command-output paging uses — not a private exec("less") path.
//   - The COMMANDS section is GROUP-AWARE, so the root's help groups
//     (wireHelpGroups) survive the template swap.
//   - `gen-man` emits real *.1 man pages via cobra/doc (unaffected by the ANSI
//     help template — GenManTree reads command fields, not the template). This
//     pulls the go-md2man dependency; recorded in build/mvp/versions.md.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"

	"github.com/sufield/stave/internal/cli/ui"
)

// Annotation keys for the man sections Cobra has no native field for. Populate
// them via cobra.Command.Annotations to render OUTPUT / EXIT STATUS / FILES /
// SEE ALSO; absent annotations simply omit the section.
const (
	AnnExitStatus = "man.exitStatus"
	AnnOutput     = "man.output"
	AnnFiles      = "man.files"
	AnnSeeAlso    = "man.seeAlso"
)

func init() {
	cobra.AddTemplateFunc("styleHeading", func(s string) string {
		h := strings.ToUpper(s)
		// Bold only (never force a color), gated by the repo's single color
		// decision so escapes stay out of `--help | cat`, redirects, and CI.
		// Survives `less -R`.
		if !ui.CanColor(os.Stdout) {
			return h
		}
		return "\x1b[1m" + h + "\x1b[0m"
	})
}

// manHelpTemplate renders help in man-page section order. The COMMANDS section
// mirrors Cobra's own group-aware rendering so wireHelpGroups still shows.
const manHelpTemplate = `{{styleHeading "name"}}
    {{.Name}}{{with .Short}} - {{.}}{{end}}
{{if .Runnable}}
{{styleHeading "synopsis"}}
    {{.UseLine}}
{{end}}{{with .Long}}
{{styleHeading "description"}}
    {{. | trimTrailingWhitespaces}}
{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}
{{styleHeading "commands"}}{{range $cmds}}{{if .IsAvailableCommand}}
    {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}
{{else}}{{range $group := .Groups}}
{{styleHeading $group.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) .IsAvailableCommand)}}
    {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}
{{end}}{{if not .AllChildCommandsHaveGroup}}
{{styleHeading "additional commands"}}{{range $cmds}}{{if (and (eq .GroupID "") .IsAvailableCommand)}}
    {{rpad .Name .NamePadding}} {{.Short}}{{end}}{{end}}
{{end}}{{end}}
{{end}}{{if .HasExample}}
{{styleHeading "examples"}}
{{.Example | trimTrailingWhitespaces}}
{{end}}{{if .HasAvailableLocalFlags}}
{{styleHeading "options"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}{{if .HasAvailableInheritedFlags}}
{{styleHeading "global options"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}{{with index .Annotations "` + AnnOutput + `"}}
{{styleHeading "output"}}
    {{.}}
{{end}}{{with index .Annotations "` + AnnExitStatus + `"}}
{{styleHeading "exit status"}}
{{.}}
{{end}}{{with index .Annotations "` + AnnFiles + `"}}
{{styleHeading "files"}}
    {{.}}
{{end}}{{with index .Annotations "` + AnnSeeAlso + `"}}
{{styleHeading "see also"}}
    {{.}}
{{else}}{{if .HasAvailableSubCommands}}
{{styleHeading "see also"}}
    Use "{{.CommandPath}} [command] --help" for details on a subcommand.
{{end}}{{end}}`

// ApplyManStyle installs the man-page-style help template on the whole command
// tree and pages the rendered help through the shared pager when stdout is a
// terminal (plain and unpaged otherwise). Call once on the root command.
func ApplyManStyle(root *cobra.Command) {
	// Capture the DEFAULT-template renderer BEFORE installing the man template,
	// so non-interactive help can fall back to it.
	base := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		out := c.OutOrStdout()
		// Non-interactive output (pipes, redirects, CI, the CLI-docs generator
		// that scrapes `--help`, and golden tests) gets the STABLE default cobra
		// help — they depend on its "Usage:/Available Commands:/Flags:" shape.
		// Only an interactive terminal gets the man-page styling + paging, so the
		// styling never reaches machine consumers.
		if !ui.IsTerminal(out) {
			base(c, args)
			return
		}
		c.SetHelpTemplate(manHelpTemplate)
		defer c.SetHelpTemplate("") // restore the default template afterwards
		pw, closePager := ui.NewPager(context.Background(), out, true)
		c.SetOut(pw)
		base(c, args)
		c.SetOut(out)
		_ = closePager()
	})
}

// NewGenManCmd generates real man pages (stave.1, stave-apply.1, …) into DIR.
// Wired onto root as hidden: `stave gen-man ./man && man ./man/stave-apply.1`.
func NewGenManCmd(root *cobra.Command, version string) *cobra.Command {
	return &cobra.Command{
		Use:   "gen-man DIR",
		Short: "Generate man pages for the command tree",
		Long: `Generate troff man pages (*.1) for every command in the tree into DIR.

The pages are produced from command metadata (name, description, flags), so they
stay in sync with the binary and are unaffected by the styled --help template.
Useful for 'man stave-apply' and offline reference.

Exit codes:
  0  Man pages written
  1  Could not create DIR or generate the pages`,
		Example:       "  stave gen-man ./man\n  man ./man/stave-apply.1",
		Hidden:        true,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			if err := os.MkdirAll(args[0], 0o750); err != nil {
				return fmt.Errorf("create man directory: %w", err)
			}
			header := &doc.GenManHeader{
				Title:   "STAVE",
				Section: "1",
				Source:  "Stave " + version,
				Manual:  "Stave Manual",
			}
			if err := doc.GenManTree(root, header, args[0]); err != nil {
				return fmt.Errorf("generate man pages: %w", err)
			}
			return nil
		},
	}
}
