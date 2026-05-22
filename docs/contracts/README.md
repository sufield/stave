# Stave observation contracts

Stave evaluates `obs.v0.1` observation snapshots produced by upstream
collectors (Steampipe, Pulumi, cloud collectors, etc.). The documents
in this directory describe the per-platform observation shapes those
collectors must emit so Stave's controls can evaluate them.

| Contract | Platform |
|---|---|
| [`active-directory.md`](./active-directory.md) | Active Directory |
| [`cisco-ios.md`](./cisco-ios.md) | Cisco IOS |
| [`eks.md`](./eks.md) | Amazon EKS |
| [`k8s.md`](./k8s.md) | Kubernetes |
| [`vsphere.md`](./vsphere.md) | VMware vSphere |

## Versioning policy

These are **stable contracts**. Once a field appears in a contract it
is bound by these rules:

* **Additive change is always allowed.** Stave may consume new fields
  at any time. Producers and consumers MUST tolerate fields they do
  not recognise.
* **Removing or renaming a field is a breaking change.** It is not
  permitted on the existing contract. If unavoidable, the contract is
  re-released under a versioned id alongside the original.
* **Tightening a field's type is a breaking change.** Widening (e.g.
  adding a new enum value) is allowed; narrowing requires the same
  versioned treatment as a rename.

Producers should be permissive about unknown fields so additive
changes don't require an integrator rebuild.
