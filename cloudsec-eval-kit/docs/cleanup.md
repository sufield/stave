# Cleanup

## Tear Down

```bash
cd terraform/
terraform destroy -auto-approve
```

This takes ~5 minutes. All resources deployed by SadCloud are removed.

## Verify

After `terraform destroy` completes:

1. Check the AWS Console → EC2 → Instances: no SadCloud instances
2. Check S3: no SadCloud buckets
3. Check OpenSearch: no SadCloud domains
4. Check IAM → Roles: no SadCloud roles
5. Check KMS: customer-managed keys marked for deletion (30-day wait)

## Manual Cleanup

If `terraform destroy` fails (state drift, timeout):

- Delete resources manually via the AWS Console
- Remove the Terraform state file: `rm terraform.tfstate*`
- Re-run `terraform destroy` to catch any remaining resources

## KMS Key Note

KMS keys cannot be deleted immediately — AWS enforces a 7–30 day
waiting period. The keys are scheduled for deletion by
`terraform destroy` but will appear in the KMS console until the
waiting period expires. They are disabled and non-functional during
this period.
