// Package s3 implements the [harness.ServiceExperiment] for S3
// bucket access. It is the first service in the experiment's
// dependency order: most fixtures, simplest policy model, highest
// confidence baseline.
//
// Three Z3 queries collapse the S3 CEL surface:
//
//   - public_access — a wildcard principal can reach the bucket
//     under conditions that do not narrow the caller (Allow with
//     Principal "*" and no scoping Condition, ACL public-read /
//     public-read-write, public_access_block off).
//   - cross_account_access — a principal from a different account
//     is granted access without an org-bound Condition.
//   - encryption_compliance — the bucket has the required
//     server-side-encryption algorithm. This is a simple property
//     check; Z3 adds no value over CEL but it stays in the map so
//     the harness exercises the trivial-case path.
//
// Control IDs in [Experiment.ControlMapping] are populated from
// the actual catalog (`stave controls list --format json` filtered
// by service=="s3"). The mapping currently covers the public-
// access and cross-account families surfaced by the catalog at
// the time of writing; new controls added later need an entry
// here before they participate in the comparison.
package s3

// queryPublicAccess is the Z3 query name the s3 model emits for
// public-bucket reachability. Multiple CEL controls in
// ControlMapping resolve to this query so a single Z3 SAT verdict
// agrees with any matching CEL fail.
const (
	queryPublicAccess         = "public_access"
	queryCrossAccountAccess   = "cross_account_access"
	queryEncryptionCompliance = "encryption_compliance"
)

// ControlMapping returns the Stave control ID → Z3 query name
// mapping for S3. The catalog IDs are pinned here as constants;
// the discovery procedure (`stave controls list --service s3`)
// is documented in this package's README and the harness
// Makefile.
//
// Adding a new S3 control: append to this map. Forgetting the
// entry is a soft failure — the comparator skips controls that
// do not appear here, so a missing control silently disappears
// from the agreement metrics. The harness's per-service summary
// surfaces the CEL-controls count so an unexpected drop is
// visible during review.
func (e *Experiment) ControlMapping() map[string]string {
	return map[string]string{
		// Public access family.
		"CTL.S3.ACCESS.002":         queryPublicAccess,
		"CTL.S3.ACCESS.003":         queryPublicAccess,
		"CTL.S3.ACCESS.004":         queryPublicAccess,
		"CTL.S3.AUTH.READ.001":      queryPublicAccess,
		"CTL.S3.AUTH.WRITE.001":     queryPublicAccess,
		"CTL.S3.POLICY.SCOPING.001": queryPublicAccess,

		// Cross-account family.
		"CTL.S3.ACCESS.001": queryCrossAccountAccess,

		// Encryption family — simple property checks; the Z3 model
		// emits a verdict so the harness sees a trivial-case
		// agreement (every fixture should produce AGREE_PASS or
		// AGREE_FAIL with no Z3-only / CEL-only divergence).
		"CTL.S3.ENCRYPT.001": queryEncryptionCompliance,
		"CTL.S3.ENCRYPT.002": queryEncryptionCompliance,
		"CTL.S3.ENCRYPT.003": queryEncryptionCompliance,
		"CTL.S3.ENCRYPT.004": queryEncryptionCompliance,
	}
}

// CollapseRatio returns the data point the per-service report
// renders as "<celControls> CEL controls → <z3Queries> Z3 queries".
// The numbers are derived from the static [ControlMapping] so a
// future addition stays in sync without a separate update.
func (e *Experiment) CollapseRatio() (celControls, z3Queries int) {
	mapping := e.ControlMapping()
	celControls = len(mapping)
	queries := map[string]struct{}{}
	for _, q := range mapping {
		queries[q] = struct{}{}
	}
	return celControls, len(queries)
}
