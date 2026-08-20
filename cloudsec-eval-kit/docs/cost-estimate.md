# Cost Estimate

Estimated cost to run the SadCloud environment: **~$2/day**.

## Per-Service Breakdown

| Service | Resource | Estimated Cost |
|---|---|---|
| EC2 | 1 × t2.micro | ~$0.28/day (on-demand, us-east-1) |
| ELBv2 | 1 × ALB | ~$0.54/day (base charge) |
| OpenSearch | 1 × t2.micro domain | ~$0.84/day |
| KMS | 3 × CMK | ~$0.10/day |
| CloudTrail | 1 × trail | Free tier (first trail) |
| S3 | 3 × buckets | ~$0.01/day (empty buckets) |
| Config | 1 × recorder | ~$0.003/rule evaluation |
| CloudWatch | 1 × alarm | Free tier (first 10 alarms) |

**Total: ~$1.77/day** (rounded to ~$2/day for safety margin)

## Recommendations

- Deploy only during your evaluation window
- Tear down immediately after capturing results: `terraform destroy`
- Most cost comes from the ALB and OpenSearch domain
- A full evaluation (deploy → run 3 tools → tear down) takes ~1 hour,
  costing less than $0.10
