//go:build ignore

// Command extract — G0 access-graph fact extractor for Phase 7.
//
// Reads a Stave snapshot (or a pre-computed JSONL fact stream) and
// writes per-predicate `.facts` TSV files Soufflé can consume via the
// .input directives in `schema.dl`.
//
// This is the Go port of `examples/engines/souffle/convert.sh`'s
// predicate-split logic, plus the optional first hop that invokes
// `stave export-sir --format jsonl` against a snapshot directory.
//
// Usage:
//
//	# Mode A: extract from a Stave snapshot directory.
//	go run ./reasoning/souffle/iam/extract.go \
//	    -snapshot ./observations \
//	    -out      ./facts
//
//	# Mode B: split a pre-existing JSONL fact stream (trial fixture).
//	go run ./reasoning/souffle/iam/extract.go \
//	    -jsonl reasoning-specs/trials/souffle-anonymous-reachability/input.jsonl \
//	    -out   /tmp/facts
//
// Run from the repo root so the `stave` binary resolves correctly
// in -snapshot mode and the relative paths to controls/ + observations/
// behave the same way the regular CLI does.
//
// Build-ignored (//go:build ignore) so the extractor doesn't ship in
// the production binary — same convention as
// internal/tools/scope-classifier/main.go.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// declaredInputs is the union of input relations the .dl programs in
// reasoning/souffle/iam/ and examples/engines/souffle/ declare. The
// extractor pre-creates an empty .facts file for each — Soufflé treats
// missing input files as a warning, and empty files evaluate as the
// empty relation, which is the correct semantic for "the snapshot
// didn't carry this predicate."
//
// Sourced from schema.dl (G0) + the bundled examples; when schema.dl
// gains a new .input directive, append the predicate here.
var declaredInputs = []string{
	// Core asset-identification predicates.
	"has_type", "has_vendor", "has_severity",
	// IAM principal-effective permissions.
	"has_action", "has_resource",
	"has_deny_action", "has_deny_resource",
	"has_permission_action", "has_permission_resource",
	"has_condition", "has_condition_value",
	// Tags + asset-level annotations.
	"has_tag",
	// Role-assumption + trust graph.
	"can_assume",
	"cross_account_assumes",
	"trusts_service",
	"has_delegated_principal",
	"has_unknown_delegated_principal",
	"has_delegation_scope_exceeded_for",
	// Resource-policy edges.
	"resource_policy_principal",
	"resource_policy_action",
	// Cognito identity-pool mappings.
	"maps_unauth_to",
	"maps_auth_to",
	"allows_unauthenticated",
	"self_registration_unrestricted",
	// Lifecycle + provenance.
	"contributed_by",
	"is_decommissioned",
	"is_provisioned",
	"first_seen_at",
	"last_seen_at",
	// Exposure window + classification.
	"has_exposure_window",
	"has_forbidden_state",
	"has_forbidden_category",
	"has_incompatible_pair",
	"has_intent_rationale",
	"has_privilege_level",
	"has_unused_service",
	"has_data_event_logging",
	"has_mfa_enforced",
	"has_advanced_security_enabled",
	// G3 — emitted by emitAuthFacts/emitSensitivityFacts below,
	// not from the JSONL stream. Listed here so preCreateEmpty
	// is idempotent (it's a no-op for these because the G3 phase
	// already wrote them).
	"authorized",
	"sensitivity",
	// G4 — bucket hijack chain inputs, emitted by
	// emitBucketHijackFacts below.
	"is_stream_destination",
	"bucket_in_snapshot",
	"references_bucket",
	"security_telemetry_router",
	"router_update_permission",
	"has_data_perimeter_scp",
	"bucket_account",
	"router_account",
	// G9 — cross-account resource policy grants, emitted by
	// emitCrossAccountAccessFacts below.
	"grants_cross_account_access",
}

// G3 default config — mirrors stave-authorization.yaml at the
// repo root. The extractor uses these defaults unless -config
// points at a file the operator has tuned. YAML parsing is a
// future enhancement; for now the defaults are hardcoded and
// the -config flag exists as a forward-compatible placeholder.
var defaultOwnershipTagKeys = []string{"Owner", "Team"}
var defaultClassificationTagKey = "DataClassification"
var defaultHighSensitivityValues = []string{"PII", "PHI", "PCI"}

// IAM principal asset types — mirror schema.dl's is_principal_type.
// Used by the G3 emitter to discriminate principals from resources
// when generating authorized facts (tag-equality joins).
var iamPrincipalTypes = map[string]struct{}{
	"aws_iam_user":           {},
	"aws_iam_role":           {},
	"aws_iam_federated_role": {},
	"aws_iam_saml_provider":  {},
	"aws_iam_sso_config":     {},
}

// factLine matches the JSONL shape sirfacts emits. Only the three
// fields the .facts files need are mandatory; everything else is
// ignored for the split.
type factLine struct {
	Predicate string `json:"predicate"`
	Subject   string `json:"subject"`
	Object    string `json:"object"`
}

type options struct {
	jsonl       string
	snapshot    string
	controls    string
	staveBinary string
	out         string
	config      string
}

func parseFlags() *options {
	opts := &options{}
	flag.StringVar(&opts.jsonl, "jsonl", "",
		"Path to a pre-existing JSONL fact stream. Mutually exclusive with -snapshot.")
	flag.StringVar(&opts.snapshot, "snapshot", "",
		"Path to a Stave snapshot directory. Invokes `stave export-sir --format jsonl`.")
	flag.StringVar(&opts.controls, "controls", "controls",
		"Path to the control catalog directory (only used with -snapshot).")
	flag.StringVar(&opts.staveBinary, "stave", "stave",
		"Path to the stave binary (only used with -snapshot).")
	flag.StringVar(&opts.out, "out", "./facts",
		"Output directory for the per-predicate .facts files.")
	flag.StringVar(&opts.config, "config", "",
		"Path to stave-authorization.yaml. Placeholder for first iteration — defaults are hardcoded; this flag exists for forward compatibility.")
	flag.Parse()

	if opts.jsonl == "" && opts.snapshot == "" {
		fmt.Fprintln(os.Stderr, "extract: must supply either -jsonl <file> or -snapshot <dir>")
		os.Exit(2)
	}
	if opts.jsonl != "" && opts.snapshot != "" {
		fmt.Fprintln(os.Stderr, "extract: -jsonl and -snapshot are mutually exclusive")
		os.Exit(2)
	}
	return opts
}

func main() {
	opts := parseFlags()

	if err := os.MkdirAll(opts.out, 0o755); err != nil {
		fail("mkdir output dir: %v", err)
	}

	var stream io.Reader
	switch {
	case opts.jsonl != "":
		f, err := os.Open(opts.jsonl)
		if err != nil {
			fail("open jsonl: %v", err)
		}
		defer f.Close()
		stream = f

	case opts.snapshot != "":
		buf, err := runExportSIR(opts)
		if err != nil {
			fail("invoke stave export-sir: %v", err)
		}
		stream = bytes.NewReader(buf)
	}

	stats, err := split(stream, opts.out)
	if err != nil {
		fail("split JSONL: %v", err)
	}

	// G3 — derive authorized + sensitivity facts from the
	// per-asset tag data + asset type discrimination. Reads
	// has_tag.facts + has_type.facts (already written by split)
	// and writes authorized.facts + sensitivity.facts.
	g3stats, err := emitG3Facts(opts.out)
	if err != nil {
		fail("emit G3 facts: %v", err)
	}
	stats["authorized"] = g3stats["authorized"]
	stats["sensitivity"] = g3stats["sensitivity"]

	// G4 — bucket hijack chain fact extraction. Reads split
	// observation facts (bucket names, ghost booleans, asset
	// types) and writes the 8 input relations bucket_hijack.dl
	// consumes. Two static seed tables (security_telemetry_router,
	// router_update_permission) are written unconditionally;
	// six snapshot-derived relations populate from the observation
	// property paths each router type's ghost controls reference.
	g4stats, err := emitBucketHijackFacts(opts.out)
	if err != nil {
		fail("emit bucket hijack facts: %v", err)
	}
	for k, v := range g4stats {
		stats[k] = v
	}

	// G9 — cross-account resource policy grants. Joins
	// resource_policy_principal + resource_policy_action per
	// resource, filtering for external principals.
	g9stats, err := emitCrossAccountAccessFacts(opts.out)
	if err != nil {
		fail("emit cross-account access facts: %v", err)
	}
	for k, v := range g9stats {
		stats[k] = v
	}

	if err := preCreateEmpty(opts.out); err != nil {
		fail("pre-create empty facts: %v", err)
	}

	report(stats, opts.out)
}

// emitG3Facts reads has_tag.facts + has_type.facts (both produced
// by the JSONL split above) and emits authorized.facts +
// sensitivity.facts per the G3 product-decision model documented
// in docs/authorization-model.md.
//
// Authorization (default config: ownership_tag_keys = [Owner, Team]):
//
//	For each (resource, principal) pair where both carry the same
//	value under any ownership tag key, emit authorized(P, R).
//	Resources with no ownership tag are fail-open: emit
//	authorized(P, R) for EVERY principal (so untagged resources
//	don't generate false-positive unauthorized_access).
//
// Sensitivity (default config: DataClassification ∈ {PII, PHI, PCI}):
//
//	For each resource with a high-value tag, emit sensitivity(R, "high").
//	Resources without the tag emit sensitivity(R, "standard").
//
// Returns per-relation counts for the report.
func emitG3Facts(outDir string) (map[string]int, error) {
	hasTags, err := readFactPairs(filepath.Join(outDir, "has_tag.facts"))
	if err != nil {
		return nil, fmt.Errorf("read has_tag.facts: %w", err)
	}
	hasTypes, err := readFactPairs(filepath.Join(outDir, "has_type.facts"))
	if err != nil {
		return nil, fmt.Errorf("read has_type.facts: %w", err)
	}

	// Partition assets into principals + resources via has_type.
	principals := map[string]struct{}{}
	resources := map[string]struct{}{}
	for _, t := range hasTypes {
		if _, ok := iamPrincipalTypes[t.Object]; ok {
			principals[t.Subject] = struct{}{}
		} else if strings.HasPrefix(t.Object, "aws_") {
			resources[t.Subject] = struct{}{}
		}
	}

	// Index tags by asset → (tag_key → tag_value). Each tag fact
	// is "key=value"; split on the first '='.
	tagsByAsset := map[string]map[string]string{}
	for _, t := range hasTags {
		idx := strings.Index(t.Object, "=")
		if idx < 0 {
			continue
		}
		key := t.Object[:idx]
		val := t.Object[idx+1:]
		if tagsByAsset[t.Subject] == nil {
			tagsByAsset[t.Subject] = map[string]string{}
		}
		tagsByAsset[t.Subject][key] = val
	}

	// Build authorized.facts.
	authPath := filepath.Join(outDir, "authorized.facts")
	authFile, err := os.Create(authPath)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", authPath, err)
	}
	defer authFile.Close()

	authCount := 0
	// Stable iteration order for determinism.
	resList := sortedKeys(resources)
	prinList := sortedKeys(principals)

	for _, r := range resList {
		ownerValues := ownershipValues(tagsByAsset[r])
		if len(ownerValues) == 0 {
			// Fail-open: authorize every principal.
			for _, p := range prinList {
				fmt.Fprintf(authFile, "%s\t%s\n", p, r)
				authCount++
			}
			continue
		}
		// Tagged resource: authorize principals whose ownership tags
		// match ANY of the resource's ownership values.
		for _, p := range prinList {
			if hasMatchingOwnership(tagsByAsset[p], ownerValues) {
				fmt.Fprintf(authFile, "%s\t%s\n", p, r)
				authCount++
			}
		}
	}

	// Build sensitivity.facts.
	sensPath := filepath.Join(outDir, "sensitivity.facts")
	sensFile, err := os.Create(sensPath)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", sensPath, err)
	}
	defer sensFile.Close()

	highValues := map[string]struct{}{}
	for _, v := range defaultHighSensitivityValues {
		highValues[v] = struct{}{}
	}
	sensCount := 0
	for _, r := range resList {
		level := "standard"
		if v, ok := tagsByAsset[r][defaultClassificationTagKey]; ok {
			if _, okHigh := highValues[v]; okHigh {
				level = "high"
			}
		}
		fmt.Fprintf(sensFile, "%s\t%s\n", r, level)
		sensCount++
	}

	return map[string]int{
		"authorized":  authCount,
		"sensitivity": sensCount,
	}, nil
}

// ownershipValues returns the resource's set of ownership-tag values
// (the union across all configured ownership tag keys).
func ownershipValues(tags map[string]string) []string {
	if tags == nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, key := range defaultOwnershipTagKeys {
		if v, ok := tags[key]; ok {
			if _, okSeen := seen[v]; !okSeen {
				out = append(out, v)
				seen[v] = struct{}{}
			}
		}
	}
	return out
}

// hasMatchingOwnership returns true if any of the principal's
// ownership tag values intersects the resource's ownership values.
func hasMatchingOwnership(principalTags map[string]string, resourceValues []string) bool {
	if principalTags == nil {
		return false
	}
	resourceSet := map[string]struct{}{}
	for _, v := range resourceValues {
		resourceSet[v] = struct{}{}
	}
	for _, key := range defaultOwnershipTagKeys {
		if v, ok := principalTags[key]; ok {
			if _, okSet := resourceSet[v]; okSet {
				return true
			}
		}
	}
	return false
}

// readFactPairs parses a TSV .facts file into (subject, object)
// records. Empty / blank lines are skipped. Lines with fewer than
// two tab-separated fields are skipped (no malformed-line failure).
type factPair struct {
	Subject string
	Object  string
}

func readFactPairs(path string) ([]factPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Missing file is treated as empty — extract.go pre-
		// creates empty .facts for relations the JSONL didn't
		// emit, but G3 may be called before preCreateEmpty.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []factPair
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			fmt.Fprintf(os.Stderr, "extract: WARN: malformed fact line in %s: %q\n",
				filepath.Base(path), line)
			continue
		}
		out = append(out, factPair{Subject: fields[0], Object: fields[1]})
	}
	return out, nil
}

// ── G4: Bucket hijack fact extraction ──────────────────
//
// Derives the 8 input relations bucket_hijack.dl consumes
// from the observation facts the JSONL split produced.
//
//   Snapshot-derived (6): bucket_in_snapshot, references_bucket,
//     is_stream_destination, bucket_account, router_account,
//     has_data_perimeter_scp.
//
//   Static seed (2): security_telemetry_router,
//     router_update_permission.

type routerEntry struct {
	routerType    string
	bucketPred    string
	extractBucket func(string) string // nil = use value as-is; return "" to skip
	isTelemetry   bool
	updatePerm    string
}

// routerRegistry maps each service's observation property path
// for the destination bucket name to a router type key. The key
// must match between is_stream_destination, references_bucket,
// security_telemetry_router, and router_update_permission so the
// Datalog joins connect.
var routerRegistry = []routerEntry{
	// Security telemetry routers.
	{"cloudtrail", "audit.cloudtrail.s3_bucket_name", nil, true, "cloudtrail:UpdateTrail"},
	{"config", "compliance.config.delivery_s3_bucket", nil, true, "config:PutDeliveryChannel"},
	{"guardduty", "threat_detection.findings_export.destination_bucket", nil, true, "guardduty:CreatePublishingDestination"},
	{"vpc_flow_log", "network.flow_log.destination_bucket", nil, true, "ec2:CreateFlowLogs"},
	{"macie", "governance.export.s3_bucket", nil, true, "macie2:PutClassificationExportConfiguration"},
	// Data pipeline routers.
	{"firehose", "streaming.firehose.destination_bucket", nil, false, "firehose:UpdateDestination"},
	{"s3_replication", "data.s3.replication.destination_bucket", nil, false, "s3:PutReplicationConfiguration"},
	{"athena", "analytics.athena.output.s3_bucket", nil, false, "athena:UpdateWorkGroup"},
	{"sagemaker", "compute.sagemaker.output.s3_bucket", nil, false, "sagemaker:CreateTrainingJob"},
	{"codepipeline", "compute.codepipeline.artifact_store.s3_bucket", nil, false, "codepipeline:UpdatePipeline"},
	{"backup", "resilience.backup.export.s3_bucket", nil, false, "backup:UpdateRecoveryPointLifecycle"},
	{"lambda", "compute.lambda.destination.s3_bucket", nil, false, "lambda:PutFunctionEventInvokeConfig"},
	{"dms", "database.dms.target.s3_bucket", nil, false, "dms:ModifyEndpoint"},
	// Special extraction — bucket name embedded in ARN or hostname.
	{"eventbridge_s3", "governance.events.target_arn", bucketFromS3ARN, false, "events:PutTargets"},
	{"cloudfront_log", "cdn.cloudfront.logging_bucket", bucketFromCFHostname, false, "cloudfront:UpdateDistribution"},
	{"elb_access_log", "network.elb.access_log_bucket", nil, false, "elasticloadbalancing:ModifyLoadBalancerAttributes"},
}

func bucketFromS3ARN(val string) string {
	parts := strings.Split(val, ":")
	if len(parts) >= 6 && parts[2] == "s3" {
		return parts[len(parts)-1]
	}
	return ""
}

func bucketFromCFHostname(val string) string {
	return strings.TrimSuffix(val, ".s3.amazonaws.com")
}

func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 && parts[4] != "" {
		return parts[4]
	}
	return ""
}

func bucketNameFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 && parts[2] == "s3" {
		return parts[len(parts)-1]
	}
	return ""
}

// emitBucketHijackFacts reads split observation facts and writes
// the 8 .facts files bucket_hijack.dl declares as .input.
func emitBucketHijackFacts(outDir string) (map[string]int, error) {
	counts := map[string]int{}

	// Read has_type.facts to find S3 buckets and collect account IDs.
	types, err := readFactPairs(filepath.Join(outDir, "has_type.facts"))
	if err != nil {
		return nil, fmt.Errorf("read has_type.facts: %w", err)
	}

	bucketNames := map[string]struct{}{}
	bucketARNs := map[string]struct{}{}
	allAccounts := map[string]struct{}{}

	for _, t := range types {
		if acct := accountFromARN(t.Subject); acct != "" {
			allAccounts[acct] = struct{}{}
		}
		if t.Object == "aws_s3_bucket" {
			if name := bucketNameFromARN(t.Subject); name != "" {
				bucketNames[name] = struct{}{}
				bucketARNs[t.Subject] = struct{}{}
			}
		}
	}

	// bucket_in_snapshot — 1-col: every S3 bucket name in the snapshot.
	if err := writeLines(filepath.Join(outDir, "bucket_in_snapshot.facts"), sortedKeys(bucketNames), counts, "bucket_in_snapshot"); err != nil {
		return nil, err
	}

	// Scan each router type's observation facts for bucket references.
	var refRows, isdRows []string
	routerAccts := map[string]string{}

	for _, r := range routerRegistry {
		pairs, readErr := readFactPairs(filepath.Join(outDir, r.bucketPred+".facts"))
		if readErr != nil || len(pairs) == 0 {
			continue
		}
		for _, p := range pairs {
			name := p.Object
			if r.extractBucket != nil {
				name = r.extractBucket(name)
			}
			if name == "" {
				continue
			}
			routerARN := p.Subject
			refRows = append(refRows, fmt.Sprintf("%s\t%s\t%s", routerARN, name, r.routerType))
			isdRows = append(isdRows, fmt.Sprintf("arn:aws:s3:::%s\t%s\t%s", name, routerARN, r.routerType))

			if acct := accountFromARN(routerARN); acct != "" {
				routerAccts[routerARN] = acct
			}
		}
	}

	// references_bucket — 3-col: router, bucket_name, router_type.
	slices.Sort(refRows)
	if err := writeLines(filepath.Join(outDir, "references_bucket.facts"), refRows, counts, "references_bucket"); err != nil {
		return nil, err
	}

	// is_stream_destination — 3-col: bucket_arn, router, router_type.
	slices.Sort(isdRows)
	if err := writeLines(filepath.Join(outDir, "is_stream_destination.facts"), isdRows, counts, "is_stream_destination"); err != nil {
		return nil, err
	}

	// security_telemetry_router — 1-col static seed.
	var telemetryRows []string
	for _, r := range routerRegistry {
		if r.isTelemetry {
			telemetryRows = append(telemetryRows, r.routerType)
		}
	}
	if err := writeLines(filepath.Join(outDir, "security_telemetry_router.facts"), telemetryRows, counts, "security_telemetry_router"); err != nil {
		return nil, err
	}

	// router_update_permission — 2-col static seed.
	var permRows []string
	for _, r := range routerRegistry {
		permRows = append(permRows, fmt.Sprintf("%s\t%s", r.routerType, r.updatePerm))
	}
	if err := writeLines(filepath.Join(outDir, "router_update_permission.facts"), permRows, counts, "router_update_permission"); err != nil {
		return nil, err
	}

	// bucket_account — 2-col. S3 ARNs lack account IDs
	// (arn:aws:s3:::name has empty parts[4]). Resolve per-bucket
	// when possible; fall back to single-account inference.
	baRows := resolveBucketAccounts(bucketARNs, allAccounts)
	if err := writeLines(filepath.Join(outDir, "bucket_account.facts"), baRows, counts, "bucket_account"); err != nil {
		return nil, err
	}

	// router_account — 2-col: parsed from router ARNs.
	raKeys := sortedKeys(func() map[string]struct{} {
		m := make(map[string]struct{}, len(routerAccts))
		for k := range routerAccts {
			m[k] = struct{}{}
		}
		return m
	}())
	var raRows []string
	for _, router := range raKeys {
		raRows = append(raRows, fmt.Sprintf("%s\t%s", router, routerAccts[router]))
	}
	if err := writeLines(filepath.Join(outDir, "router_account.facts"), raRows, counts, "router_account"); err != nil {
		return nil, err
	}

	// has_data_perimeter_scp — 1-col. If any organization asset has
	// identity.scp.has_data_perimeter_s3 = true, emit for all
	// accounts in the snapshot (SCP covers the whole org).
	dpPairs, _ := readFactPairs(filepath.Join(outDir, "identity.scp.has_data_perimeter_s3.facts"))
	hasPerimeter := false
	for _, p := range dpPairs {
		if p.Object == "true" {
			hasPerimeter = true
			break
		}
	}
	var dpRows []string
	if hasPerimeter {
		for _, acct := range sortedKeys(allAccounts) {
			dpRows = append(dpRows, acct)
		}
	}
	if err := writeLines(filepath.Join(outDir, "has_data_perimeter_scp.facts"), dpRows, counts, "has_data_perimeter_scp"); err != nil {
		return nil, err
	}

	return counts, nil
}

// resolveBucketAccounts maps each S3 bucket ARN to its owning
// account. S3 ARNs carry no account ID (arn:aws:s3:::name →
// parts[4] is ""), so the extractor must infer ownership.
//
// Strategy:
//  1. Single-account snapshot: all buckets belong to that account.
//  2. Multi-account snapshot: per-bucket resolution is not possible
//     from the fact stream alone (the observation source metadata
//     isn't projected into facts). Emit nothing and warn — the
//     operator sees the gap instead of getting silently wrong
//     cross-account classifications.
//
// ponytail: per-bucket ownership from observation source metadata
// when the SIR gains a per-asset source_account field.
func resolveBucketAccounts(bucketARNs, allAccounts map[string]struct{}) []string {
	if len(bucketARNs) == 0 {
		return nil
	}
	if len(allAccounts) == 1 {
		var acct string
		for a := range allAccounts {
			acct = a
		}
		rows := make([]string, 0, len(bucketARNs))
		for _, arn := range sortedKeys(bucketARNs) {
			rows = append(rows, fmt.Sprintf("%s\t%s", arn, acct))
		}
		return rows
	}
	if len(allAccounts) > 1 {
		fmt.Fprintf(os.Stderr,
			"extract: WARN: %d accounts in snapshot — bucket_account.facts will be empty; "+
				"S3 cross-account and bucket-hijack chain queries may produce incomplete results\n",
			len(allAccounts))
	}
	return nil
}

// ── G9: Cross-account resource policy grants ─────────────
//
// Joins resource_policy_principal × resource_policy_action per
// resource, filtering for external principals. Emits a 4-column
// relation: (resource, external_principal, action, grant_type).
//
// ponytail: over-approximates — products principal×action per
// resource, not per policy statement. Acceptable: same detection
// model as Prowler/ScoutSuite. Tighten with statement-indexed
// facts if false positives surface in practice.

func emitCrossAccountAccessFacts(outDir string) (map[string]int, error) {
	counts := map[string]int{}

	principals, err := readFactPairs(filepath.Join(outDir, "resource_policy_principal.facts"))
	if err != nil {
		return nil, fmt.Errorf("read resource_policy_principal.facts: %w", err)
	}
	actions, err := readFactPairs(filepath.Join(outDir, "resource_policy_action.facts"))
	if err != nil {
		return nil, fmt.Errorf("read resource_policy_action.facts: %w", err)
	}

	// Group by resource.
	principalsByRes := map[string][]string{}
	for _, p := range principals {
		principalsByRes[p.Subject] = append(principalsByRes[p.Subject], p.Object)
	}
	actionsByRes := map[string][]string{}
	for _, a := range actions {
		actionsByRes[a.Subject] = append(actionsByRes[a.Subject], a.Object)
	}

	// Read bucket_account for S3 resources (ARN lacks account).
	bucketAccts := map[string]string{}
	baPairs, _ := readFactPairs(filepath.Join(outDir, "bucket_account.facts"))
	for _, p := range baPairs {
		bucketAccts[p.Subject] = p.Object
	}

	seen := map[string]struct{}{}
	var rows []string
	for resource, resPrincipals := range principalsByRes {
		resActions := actionsByRes[resource]
		if len(resActions) == 0 {
			continue
		}
		resAcct := accountFromARN(resource)
		if resAcct == "" {
			resAcct = bucketAccts[resource]
		}

		for _, principal := range resPrincipals {
			gt := classifyGrantType(principal, resAcct)
			if gt == "" {
				continue
			}
			for _, action := range resActions {
				row := fmt.Sprintf("%s\t%s\t%s\t%s", resource, principal, action, gt)
				if _, dup := seen[row]; dup {
					continue
				}
				seen[row] = struct{}{}
				rows = append(rows, row)
			}
		}
	}
	slices.Sort(rows)
	if err := writeLines(filepath.Join(outDir, "grants_cross_account_access.facts"), rows, counts, "grants_cross_account_access"); err != nil {
		return nil, err
	}
	return counts, nil
}

// classifyGrantType determines the grant type for a principal on a
// resource owned by resAcct. Returns "" if same-account (not external).
//
// Grant types: "public" (*), "explicit" (cross-account ARN),
// "federated" (OIDC/SAML/Cognito IdP), "canonical_user" (S3
// canonical user ID).
func classifyGrantType(principal, resAcct string) string {
	if principal == "*" {
		return "public"
	}
	// Service principals (lambda.amazonaws.com, etc.) are AWS
	// service-to-service trust, not cross-account grants.
	if isServicePrincipal(principal) {
		return ""
	}
	prinAcct := accountFromARN(principal)
	if prinAcct == "" {
		// Non-ARN principal. Federated IdPs and canonical user IDs
		// are external access paths — emit them so downstream chain
		// queries see the edge.
		if isCanonicalUserID(principal) {
			return "canonical_user"
		}
		// Remaining non-ARN, non-service principals are federation
		// providers (OIDC, SAML, Cognito).
		return "federated"
	}
	if resAcct == "" {
		return "explicit"
	}
	if prinAcct == resAcct {
		return ""
	}
	return "explicit"
}

// isServicePrincipal returns true for AWS service principals
// (e.g. "lambda.amazonaws.com", "s3.amazonaws.com"). These
// represent AWS service-to-service trust, not external access.
func isServicePrincipal(p string) bool {
	return strings.HasSuffix(p, ".amazonaws.com")
}

// isCanonicalUserID returns true for S3 canonical user IDs —
// 64-character hex strings used in bucket ACLs for cross-account
// grants.
func isCanonicalUserID(p string) bool {
	if len(p) != 64 {
		return false
	}
	for _, c := range p {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// writeLines writes rows to a .facts file and updates counts.
func writeLines(path string, rows []string, counts map[string]int, key string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	for _, row := range rows {
		fmt.Fprintln(f, row)
	}
	counts[key] = len(rows)
	return nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// runExportSIR invokes `stave export-sir --format jsonl --controls ... --observations ...`
// and returns the captured stdout. Errors include stderr for triage.
func runExportSIR(opts *options) ([]byte, error) {
	args := []string{
		"export-sir",
		"--format", "jsonl",
		"--controls", opts.controls,
		"--observations", opts.snapshot,
	}
	cmd := exec.Command(opts.staveBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\nstderr: %s",
			opts.staveBinary, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// split reads the JSONL stream and writes one .facts file per
// distinct predicate. Each .facts row is TSV: subject \t object.
// Returns per-predicate row counts for the report.
func split(r io.Reader, outDir string) (map[string]int, error) {
	// Buffer per predicate; flush at end so each .facts file gets
	// one Open+Write cycle rather than one per line.
	buffers := map[string]*bytes.Buffer{}
	counts := map[string]int{}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var f factLine
		if err := json.Unmarshal(line, &f); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if f.Predicate == "" {
			continue
		}
		buf, ok := buffers[f.Predicate]
		if !ok {
			buf = &bytes.Buffer{}
			buffers[f.Predicate] = buf
		}
		// TSV: subject\tobject\n. Sirfacts sanitizes embedded
		// whitespace at emit-time, but TSV is fragile to literal
		// tabs in symbols — replace defensively.
		subj := strings.ReplaceAll(f.Subject, "\t", " ")
		obj := strings.ReplaceAll(f.Object, "\t", " ")
		fmt.Fprintf(buf, "%s\t%s\n", subj, obj)
		counts[f.Predicate]++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	// Determinism: write predicates in sorted order so the report
	// output is stable across runs.
	names := make([]string, 0, len(buffers))
	for p := range buffers {
		names = append(names, p)
	}
	slices.Sort(names)

	for _, pred := range names {
		path := filepath.Join(outDir, pred+".facts")
		if err := os.WriteFile(path, buffers[pred].Bytes(), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	}
	return counts, nil
}

// preCreateEmpty touches one empty .facts file per declared input
// relation that the JSONL stream didn't emit. Matches convert.sh
// behavior — Soufflé warns on missing input files but evaluates
// empty files as the empty relation.
func preCreateEmpty(outDir string) error {
	for _, pred := range declaredInputs {
		path := filepath.Join(outDir, pred+".facts")
		if _, err := os.Stat(path); err == nil {
			continue
		}
		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("touch %s: %w", path, err)
		}
		f.Close()
	}
	return nil
}

func report(counts map[string]int, outDir string) {
	total := 0
	for _, n := range counts {
		total += n
	}

	// Sorted iteration for stable output.
	preds := make([]string, 0, len(counts))
	for p := range counts {
		preds = append(preds, p)
	}
	slices.Sort(preds)

	fmt.Printf("Wrote %d .facts files to %s\n", len(counts), outDir)
	fmt.Printf("Total emitted facts: %d\n", total)
	if len(preds) > 0 {
		fmt.Println("Per-predicate counts (emitted only; empties pre-created from declaredInputs):")
		for _, p := range preds {
			fmt.Printf("  %-40s %d\n", p, counts[p])
		}
	}

	// Surface any predicates the JSONL emitted that aren't in the
	// declared-inputs list. This is the drift gate: a new sirfacts
	// predicate appearing in JSONL but not in schema.dl/declaredInputs
	// indicates the schema is stale.
	known := map[string]struct{}{}
	for _, p := range declaredInputs {
		known[p] = struct{}{}
	}
	var undeclared []string
	for _, p := range preds {
		if _, ok := known[p]; !ok {
			undeclared = append(undeclared, p)
		}
	}
	if len(undeclared) > 0 {
		fmt.Println()
		fmt.Println("WARN: predicates emitted by sirfacts but NOT declared in schema.dl/declaredInputs:")
		for _, p := range undeclared {
			fmt.Printf("  %s\n", p)
		}
		fmt.Println("Add these to declaredInputs + schema.dl if downstream programs need them.")
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "extract: "+format+"\n", args...)
	os.Exit(1)
}
