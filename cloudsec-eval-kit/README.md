# CloudSec Eval Kit

A standardized AWS environment for evaluating cloud security tools.

## What This Is

A Terraform-deployed AWS environment containing **30 documented
misconfigurations** across **8 services**, including **5 multi-resource
attack paths**. Each misconfiguration has a unique ID, a description,
a severity rating, and a manual verification method.

## What It's For

When evaluating cloud security tools — during a POC, a vendor
comparison, or an internal assessment — this environment provides
uniform ground. Every tool runs against the same misconfigurations.
You compare results, not demos.

## Quick Start

```bash
# 1. Deploy (~10 min, ~$2/day)
cd terraform/
terraform init && terraform apply

# 2. Run your tools against the deployed account

# 3. Fill in the scorecard
cp scorecard/template.csv my-evaluation.csv
# Edit my-evaluation.csv: mark each finding FOUND / MISSED / PARTIAL / N/A

# 4. Compare
# Atomic score: X / 30
# Compound score: X / 5
```

## Ground Truth

See [`ground-truth/`](ground-truth/) for the full list of
misconfigurations, severity ratings, and manual verification steps.

- **30 atomic findings** — individual misconfigurations, each
  console-verifiable
- **5 compound paths** — multi-resource attack chains that require
  connecting findings across services

## Services Covered

| Service | Entries | Example Finding |
|---|---|---|
| S3 | 3 | Bucket policy does not enforce TLS |
| IAM | 11 | Wildcard trust policy (Principal:*) |
| CloudTrail | 4 | Log file validation disabled |
| KMS | 2 | Key rotation disabled |
| EC2 | 4 | Security group allows 0.0.0.0/0 |
| ELBv2 | 3 | Outdated TLS policy |
| OpenSearch | 2 | Open access policy |
| Config | 1 | Not recording all resource types |

## Reference Results

[`results/stave.csv`](results/stave.csv) is a completed scorecard
using [Stave](https://github.com/sufield/stave). This is the first
filled-in example so you can see what a scorecard looks like.

Stave atomic score: 30/30. Compound score: 3/5.

## Scoring

For each ground truth entry, mark your tool's result:

| Value | Meaning |
|---|---|
| **FOUND** | Tool produced a matching finding |
| **MISSED** | Tool did not detect this misconfiguration |
| **PARTIAL** | Tool found something related but not equivalent |
| **N/A** | Tool does not cover this service |

See [`scorecard/instructions.md`](scorecard/instructions.md) for
detailed guidance on mapping tool findings to ground truth entries.

## Cost and Cleanup

- **Estimated cost:** ~$2/day (ALB + OpenSearch + EC2 t2.micro)
- **Teardown:** `terraform destroy` (~5 min)
- **Recommendation:** deploy only during your evaluation window

See [`docs/cost-estimate.md`](docs/cost-estimate.md) for per-service
breakdown.

## Contributing Your Results

Optional. If you'd like to share your evaluation:

1. Copy `scorecard/template.csv` to `results/<tool-name>.csv`
2. Fill in your tool's findings
3. Add a header comment with tool name, version, and date
4. Submit a PR

Your results are yours by default. Contributing is a choice.

## Infrastructure Source

The Terraform modules are from [NCC Group's SadCloud](https://github.com/nccgroup/sadcloud),
an open-source collection of intentionally vulnerable AWS configurations.
The environment is deployed exactly as SadCloud specifies — no modifications.

## License

Apache 2.0
