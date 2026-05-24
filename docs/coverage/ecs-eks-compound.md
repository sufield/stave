# ECS / EKS compound coverage map

Maps the AWS compound control authoring plan's Phase 6 (ECS/EKS)
4 sub-families against existing Stave controls and chains. Both
services share a `properties.container.*` / `properties.k8s.*`
observation namespace and are audited together.

## Headline finding

- **ECS:** 48 atomic controls, 4 compound-scope (per classifier;
  ghost-reference family)
- **EKS:** 115 atomic controls, 11 compound-scope (per classifier;
  ghost-reference family)

Like S3, VPC, KMS, and Lambda, the per-resource observation
namespaces (`container.kind`, `container.task_role`, `k8s.cluster`,
`k8s.pod_spec`, `k8s.irsa`, etc.) don't carry the cross-asset
prefix patterns the classifier auto-detects from. The compound
surface lives in chains.

**The substantial compound surface in chains: 52 today** (with
this commit, 53):

- **ECS: 18 chains** including `ecs_cluster_compromise`,
  `ecs_container_escape`, `ecs_exec_uncontrolled`,
  `ecs_secret_lifecycle`, `ecs_service_exposed`,
  `ecs_ssrf_credential_theft`, `ecs_privileged_escape`, etc.
- **EKS: 34 chains** including `eks_irsa_unsafe`,
  `eks_node_imds_unsafe`, `eks_netpol_isolation_collapsed`,
  `eks_netpol_open`, `eks_fargate_misconfigured`,
  `eks_federation_unsafe`, `eks_multicluster_admin_sprawl`,
  `eks_pod_secret_lifecycle_exposure` (NEW this commit), etc.

## Plan sub-family coverage

| # | Sub-family | Status | Existing chain(s) |
|---|---|---|---|
| 1 | Task role + execution role composition | covered | ECS: `ecs_cluster_compromise`, `ecs_ssrf_credential_theft` (task + IMDS); EKS: `eks_irsa_unsafe` (IRSA + audience scoping) |
| 2 | Pod identity / IRSA + node IAM role | covered | EKS: `eks_irsa_unsafe`, `eks_node_imds_unsafe`, `eks_federation_unsafe` |
| 3 | Secrets manager + task role + secret policy | covered (this commit) | ECS: `ecs_secret_lifecycle` (taskdef secret broken ref + SSM insecure); EKS: **NEW** `eks_pod_secret_lifecycle_exposure` (SATOKEN.AUTOMOUNT + SECRETS.ENCRYPT + SECRETS.ROTATION conjunction) |
| 4 | Network policy + pod + service composition | covered | EKS: `eks_netpol_isolation_collapsed` (no default-deny + ingress-only + wide NS selector), `eks_netpol_open` |

**Summary:** 4 covered, 0 partial, 0 gap. After this commit, every
plan sub-family is chain-covered on at least one of ECS or EKS;
sub-family 3 now has both ECS and EKS variants.

## What this commit ships

- **1 net-new chain:** `chains/eks_pod_secret_lifecycle_exposure.yaml`
  (sub-family 3, EKS variant — auto-mounted SA tokens + no
  envelope encryption + no rotation conjunction). Threshold 2;
  severity critical; pre container_code_execution; post
  iam_credential_theft.

## Why ~20 net-new wasn't the right target

The plan sized Phase 6 at ~20 net-new compound controls. Audit
reveals 52 existing chains across ECS+EKS substantially cover
all 4 sub-families:

1. Existing chains were under-counted in the original sizing
   (which used per-service-domain compound-control counts, not
   chain inventory).
2. Container/K8s observations are per-resource by design (the
   k8s.pod_spec, k8s.irsa, container.task_role fields are
   pre-computed per pod/task; the cross-asset reasoning lives
   in chains composing them).
3. Sub-family 3 had the cleanest authorable gap (EKS variant of
   secrets-lifecycle); shipped as 1 chain. The other 3
   sub-families are well-covered.

## Trajectory + service-sweep summary

Phase 6 closes the service sweep started this session. Across
Phases 2-6 (VPC, KMS, S3, Lambda, ECS/EKS):

| Phase | Service(s) | Existing chains | New chains | Coverage maps |
|---|---|---:|---:|---|
| 2 | VPC | 31 | 1 (IGW routing) | ✓ |
| 3 | KMS | 18 | 1 (multi-region drift) | ✓ |
| 4 | S3 | 16 | 1 (PHI retention) | ✓ |
| 5 | Lambda | 27 | 1 (layer supply chain) | ✓ |
| 6 | ECS/EKS | 52 | 1 (EKS pod secrets) | ✓ |
| **Total** | | **144** | **5** | **5 maps** |

**Compound-share (controls-only metric):** unchanged at
175 / 2658 = **6.77%**. Chain count grew from 585 (session start)
through 588 (post-I2) through 589 (S3) through 592 (VPC/KMS/Lambda)
to **593** (this commit). 5 service coverage maps land. IAM phase
contributed the bulk of the controls-only compound growth via
backfill + classifier prefix work; the service phases contributed
the chain-side narrative + coverage documentation.

## Notes for follow-up

- **Sub-families spanning ECS + EKS:** several chains could
  compose cross-cluster patterns (e.g., ECS task + EKS pod
  sharing a database role) but those require observation
  extractor work to link task and pod identities. Deferred.
- **Operator-side ECS-EKS workload portability chains:** when
  workloads run on both ECS and EKS, configuration drift
  between the two surfaces is itself a compound risk. No
  observation field tracks this today; deferred to an
  observation iteration.
