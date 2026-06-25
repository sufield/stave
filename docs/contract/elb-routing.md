# ELB Routing Signals

Derived observation properties for ALB/NLB routing-graph controls. A collector
populates these; Stave core only reads them. The compound signals
(`tg_path_*`, `nlb_shares_*`, `auth_rule_shadowed`) are computed by the
collector using the reasoning specs under `examples/alb-routing-*` (Soufflé +
Z3, which must agree). Inspired by Doyensec CloudsecTidbits No. 5 — *Navigating
Lax Load Balancers*; validated against doyensec/ELBaph.

The compound controls read `properties.network.elb.*`; the atomic ALB controls
(001, 004, 005) read `properties.compute.elb.*` (the existing ALB namespace,
shared with `DESYNC.MODE`/`DROP.INVALID.HEADERS`). Each section notes its
namespace.

## Path equivalence — `CTL.ELB.ROUTING.PATHEQUIV.001` (006, compound)

Asset kind: `target_group`. Reachability resolves to the **instance**, so two
target groups sharing an EC2 instance are one backend; the default rule is a
path. Reasoning spec: `examples/alb-routing-path-equivalence/`.

| Field | Type | Meaning |
|-------|------|---------|
| `tg_path_controls_inconsistent` | bool | A backend instance behind this target group is reachable via a path that carries a control (auth / source-ip / WAF) **and** another path that does not. **Fail-loud: emit explicitly.** |
| `tg_path_inconsistent_dimension` | string | Which control differs: `auth`, `source_ip`, or `waf`. |
| `tg_path_controlled_rule` | string | The listener rule on the controlled path (evidence). |
| `tg_path_bypass_rule` | string | The listener rule on the bypassing path (evidence). |
| `tg_path_shared_instance` | string | The EC2 instance reachable by both paths (evidence). |

## CloudFront origin SG — `CTL.ELB.WAF.BYPASS.CF.001` (001, network arm)

Asset kind: `elb`. **Note: this control reads `properties.compute.elb.*`**
(existing namespace), unlike the compound controls which use `network.elb.*`.
Existing `is_cloudfront_origin` / `waf_requires_cf_header` cover the header
layer; this adds the network layer.

| Field | Type | Meaning |
|-------|------|---------|
| `compute.elb.cloudfront_origin_sg_public` | bool | This ALB is a CloudFront origin AND an inbound SG rule allows a public/over-broad CIDR (`0.0.0.0/0`, `::/0`, or a broad range that includes NAT-egress public IPs) rather than only the `com.amazonaws.global.cloudfront.origin-facing` managed prefix list. Catches the mixed-rule FN trap. |

## Rule shadowing — `CTL.ELB.ROUTING.RULESHADOW.001` (002)

Asset kind: `listener`. Reasoning spec: `examples/alb-routing-rule-shadow/`.

| Field | Type | Meaning |
|-------|------|---------|
| `auth_rule_shadowed` | bool | A rule with an auth action is preceded (lower priority number) by a non-auth rule whose path condition subsumes it (a rule with no path condition counts as `/*`), so the auth action never fires. |
| `auth_rule_shadowed_auth_rule` | string | The shadowed auth rule (evidence). |
| `auth_rule_shadowed_by` | string | The shadowing rule (evidence). |

## XFF preservation — `CTL.ELB.ALB.XFF.PRESERVE.001` (004)

Asset kind: `elb`.

| Field | Type | Meaning |
|-------|------|---------|
| `compute.elb.internet_facing` | bool | The ALB scheme is `internet-facing`, OR it is internal but sits behind an internet-facing NLB (NLB→ALB passthrough — the FN trap). |
| `compute.elb.xff_header_processing_mode` | string | `routing.http.xff_header_processing.mode`: `append`, `remove`, or `preserve`. `preserve` lets clients spoof X-Forwarded-For. |

## mTLS + SG — `CTL.ELB.ALB.MTLS.SG.001` (005)

Asset kind: `elb`.

| Field | Type | Meaning |
|-------|------|---------|
| `compute.elb.mtls_enabled` | bool | The ALB has a mutual-TLS (verify) listener configuration. |
| `compute.elb.sg_allows_public` | bool | An inbound SG rule (resolving nested SG references) allows `0.0.0.0/0`/`::/0`. mTLS without a network restriction loses defense-in-depth. |

## Default-rule auth bypass — `CTL.ELB.LISTENER.DEFAULTFORWARD.001` (007, extended)

Asset kind: `listener`. Extends the existing default-forward check with
target-group / instance identity.

| Field | Type | Meaning |
|-------|------|---------|
| `default_forwards_to_auth_target` | bool | The listener's default action forwards without auth to a target group whose backend instances overlap a target group that an auth-protected rule on the same listener forwards to (instance-level, not ARN-only). |

## NLB bypass — `CTL.ELB.ROUTING.NLBBYPASS.001` (008, compound)

Asset kind: `elb` (the NLB). Reasoning spec: `examples/alb-routing-nlb-bypass/`.

| Field | Type | Meaning |
|-------|------|---------|
| `nlb_shares_gated_alb_instances` | bool | This NLB forwards (L4, no rules/auth) to one or more instances that are also behind an ALB carrying security controls — resolving NLB IP targets to instances so an IP-targeted NLB pointing at the same private IPs is caught (the FN trap). |
| `nlb_bypassed_alb` | string | The gated ALB whose controls the NLB bypasses (evidence). |
| `nlb_shared_instance` | string | A shared backend instance (evidence). |
