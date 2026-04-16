# Air-Gap Design

Why offline operation is the primary design constraint, not a secondary feature.

---

## What "Air-Gapped" Means Here

The machine running Stave has no network path to the infrastructure it evaluates. No AWS API access. No Kubernetes API access. No internet connectivity. The only input is files transferred via secure mechanisms.

This is the operational reality for classified networks (SIPR, JWICS), HIPAA-regulated healthcare environments, financial institutions with strict network segmentation, and zero-trust deployments where the security tooling is not trusted with infrastructure credentials.

## Every Feature Follows from This Constraint

- **Snapshot files** instead of API queries — because there is no API to query
- **Embedded control catalog** instead of downloading from a registry — because there is no registry to reach
- **Local CEL evaluation** instead of cloud-hosted policy engine — because there is no cloud to call
- **Evidence signing with Ed25519** instead of cloud KMS — because there is no KMS service available
- **OpenMetrics output** instead of pushing to Datadog — because there is no Datadog endpoint
- **Git-based history** instead of a database — because git is universally available and requires no server
- **JSON/Markdown output** instead of a web dashboard — because there is no browser, and rendering is the consumer's responsibility

## The Consequence: Zero Operational Overhead

Stave is a single binary. No database. No configuration server. No agent. No daemon. No container runtime dependency. No cloud account.

```bash
./stave apply --snapshot snapshot.json
```

This runs on a laptop, a jump host, a classification terminal, or a CI/CD runner. The binary is the deployment artifact. The snapshot file is the input. The JSON output is the result.

This is not minimalism for aesthetic reasons. It is the minimum viable operation for environments where installing a database is a 6-month procurement process and network connectivity to a SaaS vendor is impossible.

## The Trade-Off

Air-gap design means Stave cannot:
- Query live infrastructure in real-time
- Push alerts to Slack or PagerDuty directly
- Integrate with cloud-native security services (SecurityHub, GuardDuty) in real-time
- Provide a hosted web dashboard

These capabilities exist in the ecosystem around Stave — a Python script can push OpenMetrics to Prometheus, a Jinja template can render the report JSON as HTML, a webhook can forward findings to JIRA. Stave produces structured data. The ecosystem renders and routes it.

This is the same principle behind Unix pipes: do one thing well, produce structured output, let the consumer decide what to do with it.
