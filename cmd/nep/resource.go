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
	Snapshot    string
	ResourceARN string
	Format      string
	Actions     string
}

func newResourceCmd() *cobra.Command {
	opts := &resourceOpts{Format: "table"}

	cmd := &cobra.Command{
		Use:   "resource",
		Short: "Show who has effective access to a resource",
		Long: `Show all principals with resolved effective access to a specific
resource ARN, with access path attribution (identity-based, resource
policy, or both).

Exit Codes:
  0   No non-designated access to the resource
  1   Non-designated principals have access (PHI violation)
  3   Incomplete resolution
  4   Internal error

Examples:
  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-patient-records

  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-records \
    --format json`,
		Example:       `  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runResource(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "resource ARN to query (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.Actions, "actions", "", "comma-separated action filter")

	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("resource")

	return cmd
}

func runResource(w io.Writer, opts *resourceOpts) error {
	if _, err := os.Stat(opts.Snapshot); err != nil {
		return fmt.Errorf("snapshot file not found: %s", opts.Snapshot)
	}

	// Load snapshot bundle.
	snapshots, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return errors.New("snapshot file contains no observations")
	}
	snap := &snapshots[len(snapshots)-1]

	// Build resource access index from resource policies in the snapshot.
	idx := buildResourceAccessIndex(snap)

	// Resolve identity-based access for the target resource.
	addIdentityBasedAccess(idx, snap, opts.ResourceARN)

	entries := idx.EntriesFor(opts.ResourceARN)

	switch opts.Format {
	case "json":
		if err := renderResourceJSON(w, opts.ResourceARN, entries); err != nil {
			return err
		}
	default:
		if err := renderResourceTable(w, opts.ResourceARN, entries); err != nil {
			return err
		}
	}

	// Exit code 1 if any non-designated principal has access.
	if hasNonDesignatedAccess(entries, snap) {
		return ui.ErrSecurityAuditFindings
	}
	return nil
}

// resourcePolicyPaths maps property paths where resource policy JSON
// is stored per resource type. The extractor places the policy document
// at these paths in the asset properties.
var resourcePolicyPaths = [][]string{
	{"storage", "policy_json"},          // S3 bucket policy
	{"encryption", "key_policy_json"},   // KMS key policy
	{"compute", "resource_policy_json"}, // Lambda resource policy
	{"messaging", "policy_json"},        // SQS queue / SNS topic policy
	{"secret", "resource_policy_json"},  // Secrets Manager resource policy
}

// buildResourceAccessIndex scans assets in the snapshot for resource-based
// policies and indexes the principals they grant access to.
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

// readClassActions defines which actions constitute read access per service.
var readClassActions = map[string][]string{
	"s3":             {"s3:GetObject", "s3:ListBucket"},
	"kms":            {"kms:Decrypt", "kms:GenerateDataKey"},
	"secretsmanager": {"secretsmanager:GetSecretValue"},
	"sqs":            {"sqs:ReceiveMessage"},
	"lambda":         {"lambda:InvokeFunction"},
}

// addIdentityBasedAccess scans IAM identities and checks if their resolved
// effective allows include read-class actions on the target resource ARN.
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

		input := iam.ResolutionInput{
			PrincipalARN: string(id.ID),
		}

		// Parse identity policies.
		doc, err := iam.ParsePolicyDocument(policiesJSON)
		if err != nil {
			continue
		}
		input.IdentityPolicies = []iam.PolicyDocument{doc}

		result := iam.Resolve(input)
		if result.Incomplete {
			continue
		}

		// Check if any effective allow matches a read-class action on the target.
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

// matchesReadAccess checks if a grant matches any of the read-class actions
// on the target resource ARN.
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

// designatedTags are the tag key/value pairs that mark a principal as
// designated for PHI access.
var designatedTags = []struct{ key, value string }{
	{"stave/phi-authorized", "true"},
	{"stave/role-type", "phi-processor"},
	{"stave/role-type", "administrative"},
}

// hasNonDesignatedAccess checks if any entry is from a non-designated principal.
func hasNonDesignatedAccess(entries []iam.ResourceAccessEntry, snap *asset.Snapshot) bool {
	designated := buildDesignatedSet(snap)
	for _, e := range entries {
		if e.IsPublic {
			return true
		}
		if !designated[e.PrincipalARN] {
			return true
		}
	}
	return false
}

// buildDesignatedSet builds a set of principal ARNs that carry designated tags.
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

// resolveStringProperty traverses nested maps to extract a string value.
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

// resolveMapProperty traverses nested maps to extract a map value.
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

// extractAccountID extracts the AWS account ID from an ARN string.
func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

// extractService extracts the AWS service prefix from an ARN string.
func extractService(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func renderResourceJSON(w io.Writer, resourceARN string, entries []iam.ResourceAccessEntry) error {
	out := map[string]any{
		"resource_arn":   resourceARN,
		"accessor_count": len(entries),
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

func renderResourceTable(w io.Writer, resourceARN string, entries []iam.ResourceAccessEntry) error {
	fmt.Fprintf(w, "Resource: %s\n", resourceARN)
	fmt.Fprintf(w, "Accessors: %d\n", len(entries))

	if len(entries) == 0 {
		fmt.Fprintln(w, "\nNo principals with effective access found in snapshot.")
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
