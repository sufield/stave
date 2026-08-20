# Terraform

This directory should contain the SadCloud Terraform modules.

## Setup

Clone NCC Group's SadCloud repository and copy the Terraform files here:

```bash
git clone https://github.com/nccgroup/sadcloud.git /tmp/sadcloud
cp -r /tmp/sadcloud/sadcloud/* terraform/
```

Then deploy:

```bash
cd terraform/
terraform init
terraform apply
```

## Known Issues

- **RDS:** The `db.t2.micro` instance class may not be available in all
  regions. Change to `db.t3.micro` in the RDS module variables if needed.
- **Redshift:** The `dw2.large` node type may exceed sandbox quotas.
  Disable the Redshift module if deployment fails.
- **S3 Public Access:** Account-level Block Public Access may prevent
  the S3 public bucket modules from deploying. This is expected — the
  ground truth accounts for it.

## Teardown

```bash
terraform destroy -auto-approve
```
