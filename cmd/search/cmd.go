// Package search implements `stave search <query>` — keyword-and-
// synonym ranking over the capability catalog. The catalog
// aggregates controls + chains + operational features into
// ~150-200 capability records; the search command turns user intent
// ("public S3 bucket", "expired keys", "how long was this wrong")
// into matching catalog entries.
package search

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	appcaps "github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/cli/ui"
)

// Deps holds the catalog-loading factories.
type Deps struct {
	NewCtlRepo     compose.CtlRepoFactory
	NewChainLoader compose.ChainLoaderFactory
}

type options struct {
	Query       string
	Top         int
	Format      string
	ControlsDir string
	ChainsDir   string
}

// NewCmd constructs the `search` command.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{
		Top:         10,
		Format:      "text",
		ControlsDir: "controls",
		ChainsDir:   "chains",
	}
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Find catalog entries matching a free-form intent",
		Long: `Search the capability catalog by intent. Ranks every capability
(control group, compound chain, operational feature) against the
query tokens, expanding synonyms so the user does not need to know
Stave's vocabulary first.

Scoring (per matched token, summed):
  title:        3
  use_when:     2
  keyword:      1
  description:  0.5
Phrase-verbatim hits add 5; threshold of 1.0 filters single-word
matches against long descriptions.

Use this when you know your problem but not the catalog vocabulary:
"public S3 bucket", "expired access keys", "Cognito unauthenticated
access", "CloudTrail logging disabled", "shadow admin", "orphaned
policies".

Inputs:
  <query>       Free-form intent string (required)
  --top N       Number of matches to surface (default 10)
  --format F    text (default) | json
  --controls    Control catalog directory (default: controls)
  --chains      Chain catalog directory (default: chains)

Exit codes:
  0   Matches found (or zero matches but query was well-formed)
  2   Invalid input (missing query, bad --format)
  4   Internal error (catalog load failure)
`,
		Example: `  stave search "public S3 bucket"
  stave search "how long was this misconfigured"
  stave search "shadow admin"
  stave search "kms rotation" --format json`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.Query = strings.Join(args, " ")
			return run(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}
	cmd.Flags().IntVar(&opts.Top, "top", 10, "number of matches to surface")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "control catalog directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chain catalog directory")
	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options, deps Deps) error {
	if strings.TrimSpace(opts.Query) == "" {
		return &ui.UserError{Err: errors.New("query is required")}
	}
	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		return &ui.UserError{Err: rendErr}
	}

	controls, err := compose.LoadControlsFrom(ctx, deps.NewCtlRepo, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}
	chains, err := compose.LoadChainDefinitions(ctx, deps.NewChainLoader, opts.ChainsDir)
	if err != nil {
		var notFound interface{ NotFound() bool }
		if !errors.As(err, &notFound) || !notFound.NotFound() {
			return fmt.Errorf("load chains: %w", err)
		}
		chains = nil
	}
	catalog := appcaps.Build(controls, chains)

	hits := rank(catalog, opts.Query)
	if len(hits) > opts.Top {
		hits = hits[:opts.Top]
	}

	return renderer.Render(w, searchReport{
		Query: opts.Query,
		Top:   opts.Top,
		Total: len(hits),
		Hits:  hits,
	})
}

// Hit is one ranked capability + score breakdown.
type Hit struct {
	Capability appcaps.Capability `json:"capability"`
	Score      float64            `json:"score"`
	MatchedOn  []string           `json:"matched_on,omitempty"`
}

func rank(catalog []appcaps.Capability, query string) []Hit {
	tokens := tokenise(query)
	expanded := appcaps.ExpandQuery(tokens)
	phrase := strings.ToLower(strings.TrimSpace(query))

	out := make([]Hit, 0, 32)
	for i := range catalog {
		c := &catalog[i]
		score := 0.0
		var matched []string

		titleLow := strings.ToLower(c.Title)
		useWhenLow := strings.ToLower(c.UseWhen)
		descLow := strings.ToLower(c.Description)

		// Phrase bonus — verbatim multi-word match
		if len(strings.Fields(phrase)) > 1 {
			if strings.Contains(titleLow, phrase) {
				score += 5
				matched = append(matched, "phrase:title")
			} else if strings.Contains(useWhenLow, phrase) {
				score += 4
				matched = append(matched, "phrase:use_when")
			}
		}

		// Per-token scoring against title / use_when / keywords / description
		titleHits := 0
		for _, tok := range expanded {
			if tok == "" {
				continue
			}
			if strings.Contains(titleLow, tok) {
				score += 3
				titleHits++
			}
			if strings.Contains(useWhenLow, tok) {
				score += 2
			}
			for _, kw := range c.Keywords {
				if kw == tok || strings.Contains(kw, tok) {
					score += 1
					break
				}
			}
			if strings.Contains(descLow, tok) {
				score += 0.5
			}
		}

		// Threshold of 2.0 filters single-token keyword (1.0) or
		// single-token description (0.5) noise. Requires at least a
		// title hit, a use_when hit, two keyword hits, or a phrase
		// match to surface.
		if score < 2.0 {
			continue
		}
		if titleHits > 0 {
			matched = append(matched, fmt.Sprintf("title×%d", titleHits))
		}
		out = append(out, Hit{Capability: *c, Score: score, MatchedOn: matched})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Capability.ID < out[j].Capability.ID
	})
	return out
}

func tokenise(s string) []string {
	s = strings.ToLower(s)
	var out []string
	cur := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			cur.WriteRune(r)
		default:
			if cur.Len() >= 2 {
				out = append(out, cur.String())
			}
			cur.Reset()
		}
	}
	if cur.Len() >= 2 {
		out = append(out, cur.String())
	}
	return out
}

func renderText(w io.Writer, query string, hits []Hit) error {
	if len(hits) == 0 {
		fmt.Fprintf(w, "No matches for %q. Try broader terms (e.g. \"s3\" instead of \"bucket policy\").\n", query)
		return nil
	}
	fmt.Fprintf(w, "Matches for %q (%d):\n\n", query, len(hits))
	for i := range hits {
		c := &hits[i].Capability
		fmt.Fprintf(w, "#%d  %s", i+1, c.Title)
		if c.Severity != "" {
			fmt.Fprintf(w, "   [%s]", strings.ToUpper(c.Severity))
		}
		fmt.Fprintln(w)
		if c.UseWhen != "" {
			fmt.Fprintf(w, "    Use when: %s\n", c.UseWhen)
		}
		if c.Description != "" {
			fmt.Fprintf(w, "    Detects:  %s\n", c.Description)
		}
		if c.ExampleCmd != "" {
			fmt.Fprintf(w, "    Command:  %s\n", c.ExampleCmd)
		}
		if len(c.ControlIDs) > 0 {
			n := len(c.ControlIDs)
			limit := min(n, 3)
			extra := ""
			if n > limit {
				extra = fmt.Sprintf(" (+%d more)", n-limit)
			}
			fmt.Fprintf(w, "    Controls: %s%s\n", strings.Join(c.ControlIDs[:limit], ", "), extra)
		}
		if len(c.ChainIDs) > 0 {
			fmt.Fprintf(w, "    Chains:   %s\n", strings.Join(c.ChainIDs, ", "))
		}
		fmt.Fprintln(w)
	}
	return nil
}

// Tabwriter helper kept available for future grouped output.
var _ = tabwriter.NewWriter
