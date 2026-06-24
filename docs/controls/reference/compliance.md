# Control Reference — COMPLIANCE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.COMPLIANCE.OSCAL.REPORT.CURRENT.001

**AWS SOC Compliance Report Must Be Current**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CA-2; soc2: CC9.2;

The AWS SOC 1/SOC 2 attestation the organization relies on (downloaded from AWS Artifact as a NIST OSCAL assessment-results document) must be present, unexpired, and cover the region the snapshot was taken from. SOC reports cover a rolling 12-month period; relying on a report whose coverage period ended more than 12 months ago means there is an assurance gap — compliance claims rest on stale evidence. A report that does not list the snapshot's region in scope provides no assurance for that region at all.
This control evaluates a derived `oscal_report` asset, not a cloud resource. The OSCAL JSON -> obs projection (an extractor/collector concern, not Stave core) parses `metadata.last-modified`, `metadata.document-ids`, the `reporting-period-start`/`reporting-period-end` props, and the in-scope region list, and emits the three derived signals this predicate reads: `oscal_report.present`, `oscal_report.months_since_period_end`, and `oscal_report.region_in_scope`.
The 6-to-12-month "approaching expiry" WARN band the design calls for is not a separate per-control predicate (ctrl.v1 predicates produce only VIOLATION or PASS); it surfaces as an out.v0.1 risk_signal once months_since_period_end crosses 6 but is still <= 12, the same way every numeric-threshold control exposes approaching-threshold proximity. This control encodes only the hard FAIL line at 12 months.
Fail-loud: if no OSCAL report can be located, the collector MUST emit the asset with `oscal_report.present: false` (or fail ingest) — it must never silently omit the asset, which would hide the missing-evidence finding. The present/region predicates use `ne true` (fail-closed): a missing or unknown signal is treated as a violation, not waved through.

**Remediation:** Download the current AWS SOC 2 Type II report (OSCAL format) from AWS Artifact, confirm its reporting-period-end is within the last 12 months and that the snapshot's region is listed in scope, and re-run the projection. Schedule a recurring refresh so the report is replaced before its coverage period ages past 12 months.

---

