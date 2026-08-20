# FAQ

**Can I use this for a real vendor evaluation?**

Yes. That is what it is for. Deploy the environment, run your
candidate tools, fill in the scorecard, compare results.

**Do I need to share my results?**

No. Your results are yours. Contributing to `results/` is optional.

**Can I add my own misconfigurations?**

Fork the repository and extend `ground-truth/atomic.yaml`. Or submit
a PR to add entries to a future version.

**How often is the ground truth updated?**

The ground truth is versioned. Updates are announced in the repository.
Each version is a fixed set of entries — once published, a version
does not change.

**What if a tool finds something not in the ground truth?**

That is a bonus finding. It is not scored but worth noting. It may
indicate a misconfiguration that the ground truth should include in
a future version, or it may be a false positive — verify manually.

**What if a tool misses something?**

Verify manually using the console path in the ground truth entry.
If the misconfiguration exists and the tool did not find it, mark
it MISSED. If you discover the misconfiguration was not actually
deployed (Terraform module failed), mark it N/A.

**Can I run this without deploying to AWS?**

Tools that accept JSON input can be run against the pre-captured
observation snapshots in `observations/`. Tools that require a live
AWS account need the Terraform deployment.

**What about multi-cloud (GCP, Azure)?**

This version covers AWS only. GCP and Azure environments may be
added in future versions.

**How does compound scoring work?**

A tool gets FOUND on a compound path only if it explicitly connects
the individual findings into a chain or attack path. Finding the
individual misconfigurations (the atomic entries) is separate credit.
A tool that finds GT-EC2-004 and GT-IAM-009 individually but does
not connect them into "public ingress → admin role" gets FOUND on
both atomics but MISSED on CP-002.
