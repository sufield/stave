package nep

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/iam"
)

type resourceOpts struct {
	Snapshot       string
	ResourceARN    string
	Format         string
	Actions        string
	Classification string
	ShowDesignated bool
}

func newResourceCmd() *cobra.Command {
	opts := &resourceOpts{Format: "table", Classification: "phi"}

	cmd := &cobra.Command{
		Use:   "resource",
		Short: "Show who has effective access to a resource",
		Long: `Show all principals with resolved effective access to a specific
resource ARN, with access path attribution (identity-based, resource
policy, or both).

By default shows only non-designated principals. Use --all to include
designated principals.

Exit Codes:
  0   No non-designated access to the resource
  1   Non-designated principals have access (PHI violation)
  3   Incomplete resolution
  4   Internal error

Examples:
  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-patient-records

  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-records --all

  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-records --format dot | dot -Tpng > access.png`,
		Example: `  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records
  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records --all --format dot`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runResource(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "resource ARN to query (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | dot")
	cmd.Flags().StringVar(&opts.Actions, "actions", "", "comma-separated action filter")
	cmd.Flags().StringVar(&opts.Classification, "classification", "phi", "data classification tag value to filter resources")
	cmd.Flags().BoolVar(&opts.ShowDesignated, "all", false, "show all principals including designated")
	cmd.Flags().BoolVar(&opts.ShowDesignated, "show-designated", false, "show designated principals (alias for --all)")

	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("resource")

	return cmd
}

func runResource(w io.Writer, stderr io.Writer, opts *resourceOpts) error {
	if _, err := os.Stat(opts.Snapshot); err != nil {
		return fmt.Errorf("snapshot file not found: %s", opts.Snapshot)
	}

	snapshots, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return errors.New("snapshot file contains no observations")
	}
	snap := &snapshots[len(snapshots)-1]

	// Classification tag check.
	if opts.Classification != "" {
		checkClassificationTag(stderr, snap, opts.ResourceARN, opts.Classification)
	}

	// Build resource access index.
	idx := buildResourceAccessIndex(snap)
	addIdentityBasedAccess(idx, snap, opts.ResourceARN)

	entries := idx.EntriesFor(opts.ResourceARN)
	designated := buildDesignatedSet(snap)

	// Filter to non-designated only (default).
	displayEntries := entries
	if !opts.ShowDesignated {
		displayEntries = filterNonDesignated(entries, designated)
	}

	switch opts.Format {
	case "json":
		if err := renderResourceJSON(w, opts.ResourceARN, displayEntries, opts.ShowDesignated); err != nil {
			return err
		}
	case "dot":
		if err := renderResourceDOT(w, opts.ResourceARN, entries, designated, opts.ShowDesignated); err != nil {
			return err
		}
	default:
		if err := renderResourceTable(w, opts.ResourceARN, displayEntries, opts.ShowDesignated); err != nil {
			return err
		}
	}

	if hasNonDesignatedAccess(entries, snap) {
		return ui.ErrSecurityAuditFindings
	}
	return nil
}

// checkClassificationTag warns if the resource lacks the expected classification tag.
func checkClassificationTag(stderr io.Writer, snap *asset.Snapshot, resourceARN, classification string) {
	a, ok := snap.FindAsset(resourceARN)
	if !ok {
		return
	}
	tags := resolveMapProperty(a.Properties, []string{"tags"})
	if tags == nil {
		tags = resolveMapProperty(a.Properties, []string{"storage", "tags"})
	}
	if tags == nil {
		return
	}
	if v, ok := tags["data-classification"]; ok && fmt.Sprintf("%v", v) == classification {
		return
	}
	fmt.Fprintf(stderr, "Warning: resource %s does not have tag data-classification=%s. Showing access results anyway.\n", resourceARN, classification)
}

func filterNonDesignated(entries []iam.ResourceAccessEntry, designated map[string]bool) []iam.ResourceAccessEntry {
	var filtered []iam.ResourceAccessEntry
	for i := range entries {
		if entries[i].IsPublic || !designated[entries[i].PrincipalARN] {
			filtered = append(filtered, entries[i])
		}
	}
	return filtered
}

var resourcePolicyPaths = [][]string{
	{"storage", "policy_json"},
	{"encryption", "key_policy_json"},
	{"compute", "resource_policy_json"},
	{"messaging", "policy_json"},
	{"secret", "resource_policy_json"},
}

func buildResourceAccessIndex(snap *asset.Snapshot) *iam.ResourceAccessIndex {
	idx := iam.NewResourceAccessIndex()
	for i := range snap.Assets {
		a := &snap.Assets[i]
		accountID := extractAccountID(string(a.ID))
		for _, path := range resourcePolicyPaths {
			policyJSON := resolveStringProperty(a.Properties, path)
			if policyJSON == "" {
				continue
			}
			_ = idx.AddResourcePolicy(string(a.ID), policyJSON, accountID)
		}
	}
	return idx
}

var readClassActions = map[string][]string{
	"s3":             {"s3:GetObject", "s3:ListBucket"},
	"kms":            {"kms:Decrypt", "kms:GenerateDataKey"},
	"secretsmanager": {"secretsmanager:GetSecretValue"},
	"sqs":            {"sqs:ReceiveMessage"},
	"lambda":         {"lambda:InvokeFunction"},
}

func addIdentityBasedAccess(idx *iam.ResourceAccessIndex, snap *asset.Snapshot, targetARN string) {
	targetService := extractService(targetARN)
	readActions := readClassActions[targetService]
	if len(readActions) == 0 {
		return
	}
	for i := range snap.Identities {
		id := &snap.Identities[i]
		policiesJSON := resolveStringProperty(id.Properties, []string{"identity", "policies_json"})
		if policiesJSON == "" {
			continue
		}
		input := iam.ResolutionInput{PrincipalARN: string(id.ID)}
		doc, err := iam.ParsePolicyDocument(policiesJSON)
		if err != nil {
			continue
		}
		input.IdentityPolicies = []iam.PolicyDocument{doc}
		result := iam.Resolve(input)
		if result.Incomplete {
			continue
		}
		for _, grant := range result.EffectiveAllow {
			if matchesReadAccess(grant, targetARN, readActions) {
				idx.AddEntry(string(id.ID), iam.ResourceAccessEntry{
					PrincipalARN: string(id.ID),
					Actions:      []string{grant.Action},
					GrantSource:  "identity-based",
				})
				break
			}
		}
	}
}

func matchesReadAccess(grant iam.ActionGrant, targetARN string, readActions []string) bool {
	actionMatch := false
	for _, ra := range readActions {
		if grant.Action == ra || grant.Action == "*" || strings.HasSuffix(grant.Action, ":*") {
			actionMatch = true
			break
		}
	}
	if !actionMatch {
		return false
	}
	return grant.Resource == "*" || grant.Resource == targetARN ||
		strings.HasPrefix(targetARN, strings.TrimSuffix(grant.Resource, "*"))
}

var designatedTags = []struct{ key, value string }{
	{"stave/phi-authorized", "true"},
	{"stave/role-type", "phi-processor"},
	{"stave/role-type", "administrative"},
}

func hasNonDesignatedAccess(entries []iam.ResourceAccessEntry, snap *asset.Snapshot) bool {
	designated := buildDesignatedSet(snap)
	for _, e := range entries {
		if e.IsPublic || !designated[e.PrincipalARN] {
			return true
		}
	}
	return false
}

func buildDesignatedSet(snap *asset.Snapshot) map[string]bool {
	designated := make(map[string]bool)
	for i := range snap.Identities {
		id := &snap.Identities[i]
		tags := resolveMapProperty(id.Properties, []string{"identity", "tags"})
		if tags == nil {
			continue
		}
		for _, dt := range designatedTags {
			if v, ok := tags[dt.key]; ok && fmt.Sprintf("%v", v) == dt.value {
				designated[string(id.ID)] = true
				break
			}
		}
	}
	return designated
}

func resolveStringProperty(props map[string]any, path []string) string {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			return ""
		}
	}
	s, ok := current.(string)
	if !ok {
		return ""
	}
	return s
}

func resolveMapProperty(props map[string]any, path []string) map[string]any {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[key]
		if !ok {
			return nil
		}
	}
	m, ok := current.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func extractService(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// dotQuote wraps a string in double quotes for DOT format, escaping inner quotes.
func dotQuote(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func renderResourceJSON(w io.Writer, resourceARN string, entries []iam.ResourceAccessEntry, showAll bool) error {
	out := map[string]any{
		"resource_arn":    resourceARN,
		"accessor_count":  len(entries),
		"show_designated": showAll,
	}
	if len(entries) > 0 {
		accessors := make([]map[string]any, len(entries))
		for i, e := range entries {
			accessors[i] = map[string]any{
				"principal_arn":    e.PrincipalARN,
				"actions":          e.Actions,
				"is_cross_account": e.IsCrossAccount,
				"is_public":        e.IsPublic,
			}
		}
		out["accessors"] = accessors
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderResourceTable(w io.Writer, resourceARN string, entries []iam.ResourceAccessEntry, showAll bool) error {
	if showAll {
		fmt.Fprintf(w, "ALL ACCESS — %s\n", resourceARN)
		fmt.Fprintln(w, "Showing: all principals")
	} else {
		fmt.Fprintf(w, "NON-DESIGNATED ACCESS — %s\n", resourceARN)
		fmt.Fprintln(w, "Showing: non-designated principals only  |  use --all to show all")
	}
	fmt.Fprintf(w, "Accessors: %d\n", len(entries))

	if len(entries) == 0 {
		fmt.Fprintln(w, "\nNo principals with effective access found.")
		return nil
	}

	fmt.Fprintln(w, "\nEFFECTIVE ACCESS")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "%-50s %-12s %s\n", "Principal", "Cross-acct", "Public")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	for _, e := range entries {
		crossAcct := "no"
		if e.IsCrossAccount {
			crossAcct = "yes"
		}
		public := ""
		if e.IsPublic {
			public = "YES"
		}
		fmt.Fprintf(w, "%-50s %-12s %s\n",
			truncateARN(e.PrincipalARN, 50), crossAcct, public)
	}
	return nil
}

func renderResourceDOT(w io.Writer, resourceARN string, allEntries []iam.ResourceAccessEntry, designated map[string]bool, showAll bool) error {
	fmt.Fprintln(w, "digraph PHIAccess {")
	fmt.Fprintln(w, `    rankdir=LR`)
	fmt.Fprintln(w, `    node [fontname="Helvetica" fontsize=11]`)
	fmt.Fprintln(w)

	// Resource node.
	shortRes := shortARN(resourceARN)
	fmt.Fprintf(w, "    %s [label=%s, shape=cylinder, style=filled, fillcolor=%s]\n",
		dotQuote(resourceARN),
		dotQuote(shortRes),
		dotQuote("#FAEEDA"))
	fmt.Fprintln(w)

	// Principal nodes and edges.
	for i := range allEntries {
		e := &allEntries[i]
		isDesignated := designated[e.PrincipalARN]

		if !showAll && isDesignated {
			continue
		}

		shortP := shortARN(e.PrincipalARN)
		if isDesignated {
			fmt.Fprintf(w, "    %s [label=%s, shape=box, style=filled, fillcolor=%s]\n",
				dotQuote(e.PrincipalARN),
				dotQuote(shortP+"\nDESIGNATED"),
				dotQuote("#E1F5EE"))
			fmt.Fprintf(w, "    %s -> %s\n", dotQuote(e.PrincipalARN), dotQuote(resourceARN))
		} else if e.IsCrossAccount {
			fmt.Fprintf(w, "    %s [label=%s, shape=box, style=filled, fillcolor=%s, color=%s]\n",
				dotQuote(e.PrincipalARN),
				dotQuote(shortP+"\nCROSS-ACCOUNT"),
				dotQuote("#FCEBEB"),
				dotQuote("#E24B4A"))
			fmt.Fprintf(w, "    %s -> %s [style=dashed, color=%s, label=%s]\n",
				dotQuote(e.PrincipalARN), dotQuote(resourceARN),
				dotQuote("#E24B4A"), dotQuote("cross-account"))
		} else {
			label := shortP + "\nNON-DESIGNATED"
			if e.IsPublic {
				label = "PUBLIC\nACCESS"
			}
			fmt.Fprintf(w, "    %s [label=%s, shape=box, style=filled, fillcolor=%s]\n",
				dotQuote(e.PrincipalARN),
				dotQuote(label),
				dotQuote("#FCEBEB"))
			fmt.Fprintf(w, "    %s -> %s [color=%s]\n",
				dotQuote(e.PrincipalARN), dotQuote(resourceARN),
				dotQuote("#E24B4A"))
		}
	}

	fmt.Fprintln(w, "}")
	return nil
}
