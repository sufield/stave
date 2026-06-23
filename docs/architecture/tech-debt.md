# Stave Tech-Debt Inventory

Known design debt to revisit. Add an entry when a decision is deferred;
remove it when paid down. Keep entries concrete: what, where, why it's debt,
and the fix direction.

---

## `--profile` encodes cloud-provider/service-specific values

**Principle:** Stave is a generic evaluator — it proves `ctrl.v1` predicates
against `obs.v0.1` assets and does not know what an S3 bucket or a MicroVM is.
Provider/service specificity belongs in control YAML and observation data,
**never in the CLI surface**. Stave should have no flag (or flag value) specific
to a cloud provider service.

**The debt:** `--profile` violates this. Its accepted values are a hardcoded
service enum — `aws-s3`, `aws-iam`, `aws-efs`, `gcp-gcs`, plus compliance packs
(`hipaa`, `soc2`, …) — defined in `cmd/apply/profile.go` (`Profile` constants
and the `supported:` list in the parse error). Adding a service means editing Go
and extending the enum, and the CLI now carries `aws-`/`gcp-`-shaped knowledge
of specific cloud services.

**Why it's debt, not just style:** it couples the CLI to the catalog's service
taxonomy. Every new service pack tempts a new `--profile <service>` value, and
the binary's flag surface grows with the cloud rather than staying invariant.
It also contradicts the architecture identity ("formal proof system for JSON
infrastructure, not a cloud tool").

**Fix direction:** make `--profile` provider-agnostic — accept any registered
pack id resolved from the pack registry, rather than a fixed enum mapped in
`profile.go`. The service/provider name then lives only as data (the pack id in
`internal/adapters/controls/pack/embedded/`), not as a CLI constant. Generic
directory mode (`stave apply -i <controls-dir> -o <observations-dir>`) already
satisfies the principle and is the model to converge `--profile` toward.

**Scope note:** larger than a flag rename — `--profile` currently maps each enum
value to a built-in pack and has profile e2e goldens, so the change touches
`cmd/apply/profile.go`, the registry lookup, and `cmd/apply/profile_e2e_test.go`.
Deferred; not blocking. New lab work (e.g. the Lambda MicroVM controls) already
avoids the issue by using directory mode and putting all service specificity in
the control YAML + obs data.

**Discovered:** Lambda MicroVM lab build — chose directory mode over adding a
`--profile microvm` value precisely to avoid extending this debt.
