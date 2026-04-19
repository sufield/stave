---
title: "Observation Contract"
sidebar_label: "Observation Contract"
sidebar_position: 4
description: "Stable contract for observation snapshots used by Stave."
---

# Observation Contract

The monolithic contract document was split by namespace in April 2026.
The current contract lives in [`docs/contract/`](contract/README.md).

## Where to find each domain

- **`storage.*`** (S3, GCS, Access Points, CDN-origin, `s3_ref.*`,
  `s3_upload.*`) → [contract/storage.md](contract/storage.md)
- **`identity.*`** (IAM, escalation, blast radius, trust, shadow logic,
  service wildcards, vendor trust, entitlement entropy, cross-env) →
  [contract/identity.md](contract/identity.md)
- **`reachability.*`** (anonymous paths, exfiltration, sovereignty) →
  [contract/reachability.md](contract/reachability.md)
- **CORS** (cross-service: S3, API Gateway, CloudFront, Lambda) →
  [contract/cors.md](contract/cors.md)
- **`network.*`** → [contract/network.md](contract/network.md)
- **`compute.*`** → [contract/compute.md](contract/compute.md)
- **`database.*`** → [contract/database.md](contract/database.md)
- Kubernetes (`rbac.*`, `network_policy.*`, `secrets.*`, `audit.*`) →
  [contract/kubernetes.md](contract/kubernetes.md)
- **`loadbalancer.*`, `dns.*`, `cryptography.*`, `secret.*`, `backup.*`,**
  and the compliance-expansion table → [contract/misc.md](contract/misc.md)

Envelope, asset/identity structure, MVP stability promise, and global
conventions (null vs empty, raw vs effective signals, contract vs
extractor scope, derived fields, cross-domain concerns, the
deprecation-candidate appendix) live in the
[contract README](contract/README.md).

## Why the split

The monolithic file had grown to ~1520 lines after the Prowler-coverage
and Reju-Kole iterations added multiple namespaces. Every contract
extension required reading the full document to place a new field.
The split organizes by namespace prefix, matching the `controls/`
directory's service-based organization. No semantic changes to field
definitions — purely a reorganization.

## External references

This file remains as a redirect stub. Any external link to
`docs/observation-contract.md` (PR descriptions, release notes,
blog posts) still resolves here and points readers at the new
structure. New work should link directly at the relevant
`docs/contract/<namespace>.md` file.
