// Command z3prove runs three Z3 queries against the S3
// cross-account replication configuration from a published
// tutorial (the writeup-config fixture) and against a
// remediated version of the same configuration.
//
// # Three queries
//
// Finding 1 — *non-replication principal access.* The
// destination bucket policy uses
// `Principal: "arn:aws:iam::SOURCE_ACCOUNT:root"`. In a
// resource policy, account-root delegates authorisation to
// the named account's IAM — i.e., the bucket policy admits
// any principal in that account whose IAM permissions allow
// the action. Z3 finds a witness: an intern user, an admin
// role, anyone in the source account is admitted. Expected:
// SAT on writeup-config, UNSAT on remediated.
//
// Finding 2 — *excess actions via s3:Get* wildcard.* The
// destination bucket policy grants `s3:Get*` and `s3:List*`.
// Replication only needs `s3:GetBucketVersioning`. Z3
// enumerates a witness from the ~30 other `s3:Get*` actions
// that match the wildcard but aren't replication-required.
// Expected: SAT on writeup-config, UNSAT on remediated.
//
// Finding 3 — *KMS Resource:* scope check.* The destination
// KMS key policy uses `Resource: "*"`. In a *KMS key
// policy*, `Resource: "*"` means "this key" — different
// semantics from IAM policies where `*` means "all
// resources." Z3 confirms the correct semantic: the
// replication role cannot use this key policy to encrypt
// with any *other* KMS key. Expected: UNSAT on both
// configurations — the suspicion is refuted.
//
// # Modelling note
//
// Same int-enum encoding pattern as the other Z3 provers in
// examples/. Each query has its own
// witness set; the matcher logic (action / resource /
// principal) is shared with the IAM iterations and adapted
// here for the bucket-policy domain plus a KMS-specific
// resource-match rule that respects the "Resource:* means
// this key" semantic.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aclements/go-z3/z3"
)

const (
	sourceAccount    = "111122223333"
	destAccount      = "444455556666"
	destBucketARN    = "arn:aws:s3:::destination-bucket-replication-2023"
	destKeyARN       = "arn:aws:kms:us-west-2:444455556666:key/dest-cmk-id"
	replicationRole  = "arn:aws:iam::111122223333:role/bucket-replication-role"
	otherCustomerKey = "arn:aws:kms:us-west-2:444455556666:key/customer-data-cmk"
)

type statement struct {
	Effect    string `json:"Effect"`
	Sid       string `json:"Sid,omitempty"`
	Principal any    `json:"Principal"`
	Action    any    `json:"Action"`
	Resource  any    `json:"Resource"`
}

type policyDoc struct {
	Statement []statement `json:"Statement"`
}

func main() {
	root, err := exampleRoot()
	if err != nil {
		log.Fatalf("locate example root: %v", err)
	}

	configs := []struct {
		label string
		dir   string
	}{
		{"writeup-config", filepath.Join(root, "fixtures/writeup-config/observations")},
		{"remediated-config", filepath.Join(root, "fixtures/remediated-config/observations")},
	}

	allOK := true
	for i, c := range configs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("========== %s ==========\n", c.label)
		bucketStatements, kmsStatements, err := loadPolicies(c.dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[%s] load: %v\n", c.label, err)
			os.Exit(1)
		}

		ok1 := finding1NonReplicationPrincipal(c.label, bucketStatements)
		fmt.Println()
		ok2 := finding2ExcessActions(c.label, bucketStatements)
		fmt.Println()
		ok3 := finding3KMSScopeCheck(c.label, kmsStatements)

		allOK = allOK && ok1 && ok2 && ok3
	}
	if !allOK {
		os.Exit(1)
	}
}

// finding1NonReplicationPrincipal asks: "is there a
// principal in account 111122223333 that is NOT the
// replication role but CAN perform s3:ReplicateObject on the
// destination bucket?"
//
// SAT on writeup-config (account-root admits everyone),
// UNSAT on remediated (Principal scoped to the role).
func finding1NonReplicationPrincipal(label string, statements []statement) bool {
	type witness struct {
		principal string
		intended  bool
	}
	witnesses := []witness{
		{principal: replicationRole, intended: true},
		{principal: "arn:aws:iam::111122223333:user/intern-developer"},
		{principal: "arn:aws:iam::111122223333:role/admin-role"},
		{principal: "arn:aws:iam::111122223333:user/data-analyst"},
	}

	admitted := make([]int, 0, len(witnesses))
	for i, w := range witnesses {
		for _, st := range statements {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			if !principalMatches(st.Principal, w.principal) {
				continue
			}
			if !actionMatches(stringList(st.Action), "s3:ReplicateObject") {
				continue
			}
			if !resourceMatches(stringList(st.Resource), destBucketARN+"/x.dat") {
				continue
			}
			admitted = append(admitted, i)
			break
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("principal_idx")

	intendedIdx := []int{}
	for i, w := range witnesses {
		if w.intended {
			intendedIdx = append(intendedIdx, i)
		}
	}

	admittedZ := disjunction(ctx, req, admitted, intSort)
	intendedZ := disjunction(ctx, req, intendedIdx, intSort)
	unsafe := admittedZ.And(intendedZ.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F1] z3: %v\n", label, err)
		return false
	}

	fmt.Println("--- Finding 1: non-replication principal access ---")
	fmt.Printf("  query:    is there a principal in %s that is NOT %s\n",
		sourceAccount, replicationRole)
	fmt.Printf("            but CAN perform s3:ReplicateObject on the destination?\n")
	fmt.Printf("  admitted: %d / %d witnesses\n", len(admitted), len(witnesses))

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		fmt.Printf("  verdict:  SAT — witness: %s\n", witnesses[idx].principal)
		fmt.Printf("            (account-root in the policy admits ANY principal in the account)\n")
		return label == "writeup-config"
	}
	fmt.Printf("  verdict:  UNSAT — only the replication role is admitted\n")
	return label == "remediated-config"
}

// finding2ExcessActions asks: "is there an action matching
// the s3:Get* wildcard that is NOT in the replication-
// required set but IS permitted by the destination bucket
// policy?"
//
// SAT on writeup-config (s3:Get* admits dozens of actions),
// UNSAT on remediated (the AllowRead statement was removed).
func finding2ExcessActions(label string, statements []statement) bool {
	excess := excessGetActions()

	// Witness set: each excess Get-action with the source
	// account-root principal as the (effective) caller.
	admitted := make([]int, 0, len(excess))
	for i, action := range excess {
		for _, st := range statements {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			if !principalMatches(st.Principal, "arn:aws:iam::111122223333:user/any-user") {
				continue
			}
			if !actionMatches(stringList(st.Action), action) {
				continue
			}
			if !resourceMatches(stringList(st.Resource), destBucketARN) {
				continue
			}
			admitted = append(admitted, i)
			break
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("action_idx")

	admittedZ := disjunction(ctx, req, admitted, intSort)

	s := z3.NewSolver(ctx)
	s.Assert(admittedZ)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F2] z3: %v\n", label, err)
		return false
	}

	fmt.Println("--- Finding 2: excess actions via s3:Get* wildcard ---")
	fmt.Printf("  query:    among %d s3:Get* actions, is any one\n", len(excess))
	fmt.Printf("            (a) not in replication's required set, AND\n")
	fmt.Printf("            (b) permitted by the destination bucket policy?\n")
	fmt.Printf("  admitted: %d / %d excess witnesses\n", len(admitted), len(excess))

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		fmt.Printf("  verdict:  SAT — witness: %s\n", excess[idx])
		fmt.Printf("            (the policy's Action: \"s3:Get*\" admits this action;\n")
		fmt.Printf("             replication never calls it)\n")
		return label == "writeup-config"
	}
	fmt.Printf("  verdict:  UNSAT — no excess s3:Get* action is admitted\n")
	return label == "remediated-config"
}

// finding3KMSScopeCheck asks: "does the KMS key policy's
// Resource:* grant access to KMS keys OTHER than the
// destination key itself?"
//
// In a KMS key policy, Resource:* is scoped to the key the
// policy is attached to. The matcher's resource-match rule
// for KMS key policies enforces this — the witness `keyARN
// != destKeyARN` cannot satisfy the predicate, so the result
// is UNSAT. Expected on BOTH configurations: UNSAT (the
// suspicion is refuted; the author got this right).
func finding3KMSScopeCheck(label string, statements []statement) bool {
	type witness struct {
		key   string
		isThis bool
	}
	witnesses := []witness{
		{key: destKeyARN, isThis: true},
		{key: otherCustomerKey},
		{key: "arn:aws:kms:us-west-2:444455556666:key/billing-cmk"},
	}

	admitted := make([]int, 0, len(witnesses))
	for i, w := range witnesses {
		for _, st := range statements {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			if !principalMatches(st.Principal, replicationRole) {
				continue
			}
			if !actionMatches(stringList(st.Action), "kms:Encrypt") {
				continue
			}
			if !kmsResourceMatches(stringList(st.Resource), w.key, destKeyARN) {
				continue
			}
			admitted = append(admitted, i)
			break
		}
	}

	thisKeyIdx := []int{}
	for i, w := range witnesses {
		if w.isThis {
			thisKeyIdx = append(thisKeyIdx, i)
		}
	}

	ctx := z3.NewContext(nil)
	intSort := ctx.IntSort()
	req := ctx.IntConst("key_idx")

	admittedZ := disjunction(ctx, req, admitted, intSort)
	thisKeyZ := disjunction(ctx, req, thisKeyIdx, intSort)
	unsafe := admittedZ.And(thisKeyZ.Not())

	s := z3.NewSolver(ctx)
	s.Assert(unsafe)
	sat, err := s.Check()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[%s F3] z3: %v\n", label, err)
		return false
	}

	fmt.Println("--- Finding 3: KMS Resource:* scope check ---")
	fmt.Printf("  query:    does the destination KMS key policy admit\n")
	fmt.Printf("            kms:Encrypt on a key OTHER than %s?\n", destKeyARN)
	fmt.Printf("  admitted: %d / %d witnesses (only the key policy's own key matches)\n",
		len(admitted), len(witnesses))

	if sat {
		m := s.Model()
		v := m.Eval(req, true)
		idx, _, _ := v.(z3.Int).AsInt64()
		fmt.Printf("  verdict:  SAT — witness: %s (suspicion CONFIRMED)\n", witnesses[idx].key)
		return false
	}
	fmt.Printf("  verdict:  UNSAT — KMS Resource:* scopes to the key itself only\n")
	fmt.Printf("            (suspicion REFUTED; author got this right)\n")
	return true
}

// kmsResourceMatches encodes the KMS-key-policy semantic:
// `Resource:*` in a KMS key policy means "this key only" —
// not "all keys" as it would in an IAM policy. Any other
// pattern follows the standard ARN-prefix matching.
func kmsResourceMatches(stmtResources []string, witnessKey, thisKeyARN string) bool {
	for _, r := range stmtResources {
		if r == "*" {
			return witnessKey == thisKeyARN
		}
		if r == witnessKey {
			return true
		}
		if strings.HasSuffix(r, "/*") {
			prefix := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(witnessKey, prefix+"/") {
				return true
			}
		}
	}
	return false
}

// --- Shared matcher helpers ---

// principalMatches reports whether the statement's
// Principal admits the witness principal. Account-root
// (`arn:aws:iam::ACCOUNT:root`) admits every principal in
// that account.
func principalMatches(stmtPrincipal any, witnessPrincipal string) bool {
	switch p := stmtPrincipal.(type) {
	case string:
		return p == "*" || p == witnessPrincipal || matchesAccountRoot(p, witnessPrincipal)
	case map[string]any:
		if aws, ok := p["AWS"]; ok {
			for _, arn := range stringList(aws) {
				if arn == "*" || arn == witnessPrincipal || matchesAccountRoot(arn, witnessPrincipal) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}

// matchesAccountRoot returns true if the statement principal
// is `arn:aws:iam::ACCOUNT:root` and the witness principal's
// ARN starts with `arn:aws:iam::ACCOUNT:`.
//
// In AWS resource policies, account-root delegates
// authorisation to the named account's IAM. The bucket
// policy admits any principal in that account that has the
// action via its own IAM permissions; from the resource
// policy's perspective, every principal in that account is
// admitted.
func matchesAccountRoot(stmtPrincipal, witnessPrincipal string) bool {
	if !strings.HasSuffix(stmtPrincipal, ":root") {
		return false
	}
	prefix := strings.TrimSuffix(stmtPrincipal, ":root")
	return strings.HasPrefix(witnessPrincipal, prefix+":")
}

func actionMatches(stmtActions []string, witness string) bool {
	for _, a := range stmtActions {
		if a == "*" || a == witness {
			return true
		}
		if strings.HasSuffix(a, ":*") {
			service := strings.TrimSuffix(a, ":*")
			if strings.HasPrefix(witness, service+":") {
				return true
			}
		}
		// Glob-style middle-of-name wildcard: e.g. "s3:Get*"
		// matches "s3:GetBucketAcl".
		if star := strings.Index(a, "*"); star > 0 {
			prefix := a[:star]
			if strings.HasPrefix(witness, prefix) {
				return true
			}
		}
	}
	return false
}

func resourceMatches(stmtResources []string, witness string) bool {
	for _, r := range stmtResources {
		if r == "*" || r == witness {
			return true
		}
		if strings.HasSuffix(r, "/*") {
			prefix := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(witness, prefix+"/") {
				return true
			}
		}
	}
	return false
}

func disjunction(ctx *z3.Context, key z3.Int, indices []int, sort z3.Sort) z3.Bool {
	if len(indices) == 0 {
		return ctx.FromBool(false)
	}
	first := key.Eq(ctx.FromInt(int64(indices[0]), sort).(z3.Int))
	if len(indices) == 1 {
		return first
	}
	rest := make([]z3.Bool, 0, len(indices)-1)
	for _, i := range indices[1:] {
		rest = append(rest, key.Eq(ctx.FromInt(int64(i), sort).(z3.Int)))
	}
	return first.Or(rest...)
}

func stringList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// loadPolicies reads the snapshot dir, returns the
// destination bucket's policy statements and the destination
// KMS key's key-policy statements.
func loadPolicies(snapshotsDir string) (bucket, kms []statement, err error) {
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read dir %s: %w", snapshotsDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(snapshotsDir, name))
		if err != nil {
			return nil, nil, err
		}
		var snap struct {
			Assets []struct {
				ID         string `json:"id"`
				Type       string `json:"type"`
				Properties struct {
					Storage struct {
						PolicyJSON string `json:"policy_json"`
					} `json:"storage"`
					Encryption struct {
						KeyPolicyJSON string `json:"key_policy_json"`
					} `json:"encryption"`
				} `json:"properties"`
			} `json:"assets"`
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, a := range snap.Assets {
			switch a.Type {
			case "aws_s3_bucket":
				if a.ID == destBucketARN && a.Properties.Storage.PolicyJSON != "" {
					var pol policyDoc
					if err := json.Unmarshal([]byte(a.Properties.Storage.PolicyJSON), &pol); err != nil {
						return nil, nil, err
					}
					bucket = pol.Statement
				}
			case "aws_kms_key":
				if a.ID == destKeyARN && a.Properties.Encryption.KeyPolicyJSON != "" {
					var pol policyDoc
					if err := json.Unmarshal([]byte(a.Properties.Encryption.KeyPolicyJSON), &pol); err != nil {
						return nil, nil, err
					}
					kms = pol.Statement
				}
			}
		}
	}
	if bucket == nil {
		return nil, nil, fmt.Errorf("destination bucket policy not found in %s", snapshotsDir)
	}
	if kms == nil {
		return nil, nil, fmt.Errorf("destination KMS key policy not found in %s", snapshotsDir)
	}
	return bucket, kms, nil
}

func exampleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller(0) unavailable")
	}
	return filepath.Dir(filepath.Dir(file)), nil
}
