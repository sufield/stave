package nepcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// ResourceConfig parameterizes [ResolveResourceAccess].
type ResourceConfig struct {
	Snapshot       string
	ResourceARN    string
	Format         string
	Actions        string
	Classification string
	ShowDesignated bool
}

// ResolveResourceAccess shows which principals have resolved effective access
// to a resource ARN, rendering the view (table | json | dot). It returns the
// rendered bytes, any operator warnings (for stderr), and whether any
// non-designated principal has access (the caller maps that to exit 1).
// Load/render failures stay plain (exit 4).
func ResolveResourceAccess(cfg ResourceConfig) (output []byte, warnings []string, hasFindings bool, err error) {
	if _, statErr := os.Stat(cfg.Snapshot); statErr != nil {
		return nil, nil, false, fmt.Errorf("snapshot file not found: %s", cfg.Snapshot)
	}

	snapshots, err := observations.LoadBundle(cfg.Snapshot)
	if err != nil {
		return nil, nil, false, fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return nil, nil, false, errors.New("snapshot file contains no observations")
	}
	snap := &snapshots[len(snapshots)-1]

	if cfg.Classification != "" {
		if warn := classificationWarning(snap, cfg.ResourceARN, cfg.Classification); warn != "" {
			warnings = append(warnings, warn)
		}
	}

	// Build resource access index. Per-resource policy errors surface as a
	// warning; the command still proceeds with the partial index.
	idx, idxErr := buildResourceAccessIndex(snap)
	if idxErr != nil {
		warnings = append(warnings, fmt.Sprintf("Warning: %v", idxErr))
	}
	addIdentityBasedAccess(idx, snap, cfg.ResourceARN)

	entries := idx.EntriesFor(cfg.ResourceARN)
	designated := buildDesignatedSet(snap)

	displayEntries := entries
	if !cfg.ShowDesignated {
		displayEntries = filterNonDesignated(entries, designated)
	}

	var buf bytes.Buffer
	if rErr := renderResource(cfg.Format, &buf, resourcePayload{
		ResourceARN:    cfg.ResourceARN,
		DisplayEntries: displayEntries,
		AllEntries:     entries,
		Designated:     designated,
		ShowDesignated: cfg.ShowDesignated,
	}); rErr != nil {
		return nil, warnings, false, rErr
	}

	return buf.Bytes(), warnings, hasNonDesignatedAccess(entries, snap), nil
}

// resourcePayload bundles the data each resource-mode renderer needs.
type resourcePayload struct {
	ResourceARN    string
	DisplayEntries []iam.ResourceAccessEntry
	AllEntries     []iam.ResourceAccessEntry
	Designated     map[string]bool
	ShowDesignated bool
}

// renderResource dispatches to the format-specific resource renderer.
func renderResource(format string, w io.Writer, p resourcePayload) error {
	switch format {
	case "json":
		return renderResourceJSON(w, p.ResourceARN, p.DisplayEntries, p.ShowDesignated)
	case "dot":
		return renderResourceDOT(w, p.ResourceARN, p.AllEntries, p.Designated, p.ShowDesignated)
	case "table", "":
		return renderResourceTable(w, p.ResourceARN, p.DisplayEntries, p.ShowDesignated)
	}
	return fmt.Errorf("unsupported format %q (expected: table | json | dot)", format)
}

// classificationWarning returns a warning when the resource lacks the
// expected classification tag (empty string when no warning is warranted).
func classificationWarning(snap *asset.Snapshot, resourceARN, classification string) string {
	a, ok := snap.FindAsset(resourceARN)
	if !ok {
		return ""
	}
	tags := resolveMapProperty(a.Properties, []string{"tags"})
	if tags == nil {
		tags = resolveMapProperty(a.Properties, []string{"storage", "tags"})
	}
	if tags == nil {
		return ""
	}
	if v, ok := tags["data-classification"]; ok && fmt.Sprintf("%v", v) == classification {
		return ""
	}
	return fmt.Sprintf("Warning: resource %s does not have tag data-classification=%s. Showing access results anyway.", resourceARN, classification)
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

func buildResourceAccessIndex(snap *asset.Snapshot) (*iam.ResourceAccessIndex, error) {
	idx := iam.NewResourceAccessIndex()
	var errs []error
	for i := range snap.Assets {
		a := &snap.Assets[i]
		accountID := extractAccountID(string(a.ID))
		for _, path := range resourcePolicyPaths {
			policyJSON := resolveStringProperty(a.Properties, path)
			if policyJSON == "" {
				continue
			}
			if err := iam.AddResourcePolicy(idx, string(a.ID), policyJSON, accountID); err != nil {
				errs = append(errs, fmt.Errorf("resource %s (%s): %w",
					a.ID, strings.Join(path, "."), err))
			}
		}
	}
	if len(errs) > 0 {
		return idx, fmt.Errorf("partial access index — %d policy(ies) failed to parse: %w",
			len(errs), errors.Join(errs...))
	}
	return idx, nil
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

	shortRes := shortARN(resourceARN)
	fmt.Fprintf(w, "    %s [label=%s, shape=cylinder, style=filled, fillcolor=%s]\n",
		dotQuote(resourceARN),
		dotQuote(shortRes),
		dotQuote("#FAEEDA"))
	fmt.Fprintln(w)

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
