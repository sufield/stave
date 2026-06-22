# Control Reference — LIFECYCLE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.LIFECYCLE.STAGING.STALE.001

**Stale Non-Production Resource Detected**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2; owasp_nhi: NHI1; soc2: CC8.1;

A resource tagged for non-production use (staging, dev, test, qa, sandbox, demo) is dormant or unused beyond the staleness threshold. Per-service dormancy controls (CTL.CLOUDFRONT.LIFECYCLE.DORMANT.001, CTL.APIGATEWAY.ORPHAN.API.001, etc.) fire on the lifecycle signal alone — environment-agnostic. This control adds the environment-tag dimension: a dormant resource that explicitly identifies as non-production is a higher-confidence cleanup target than a generic dormant resource. Production dormancy may be a routine artifact (warm standby, seasonal capacity); non-production dormancy is almost always abandoned shadow infrastructure. The same lifecycle fields existing per-service controls already populate (`is_dormant`, `appears_unused`, `last_request_days`, `last_deployment_days`) provide the dormancy evidence; this control filters by tag, it does not redefine staleness.

**Remediation:** 1) If no longer needed: decommission the resource — delete the asset, remove associated DNS records, remove or scope down any IAM roles attached to it, and remove any references from CI/CD pipelines or downstream consumers. 2) If still needed but intentionally idle (sprint demo retained for review, ephemeral QA harness): tag the resource with `reviewed_at: <RFC3339>` and document the expected idle duration. 3) Verify whether the resource is publicly reachable (CTL.LIFECYCLE.STAGING.EXPOSED.001 will fire if so) — public exposure on stale non-production infrastructure is the canonical NHI-offboarding failure mode.

---

