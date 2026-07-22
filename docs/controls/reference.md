# Control Reference

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`

**Total controls:** 3154
**Pack hash:** `13025497dc6be5e5e7b340fdeb8625b6bd374001f200f218112553953c7f52b0`

The full per-control detail is split by service so every page renders on
GitHub. Pick a service below.

## Summary

| Severity | Count |
|----------|-------|
| critical | 342 |
| high | 1374 |
| info | 19 |
| low | 235 |
| medium | 1184 |

| Domain | Count |
|--------|-------|
| access | 9 |
| audit | 97 |
| capacity | 3 |
| compute | 1 |
| config | 2 |
| detection | 140 |
| encryption | 119 |
| exposure | 1384 |
| governance | 646 |
| hygiene | 20 |
| identity | 606 |
| lifecycle | 31 |
| network | 48 |
| resilience | 36 |
| secrets | 4 |
| storage | 8 |

## Controls by service

| Service | Controls |
|---------|----------|
| [ACCOUNT](reference/account.md) | 3 |
| [ACM](reference/acm.md) | 8 |
| [ACMPCA](reference/acmpca.md) | 1 |
| [AD](reference/ad.md) | 40 |
| [AMPLIFY](reference/amplify.md) | 1 |
| [APIGATEWAY](reference/apigateway.md) | 105 |
| [APIGW2](reference/apigw2.md) | 2 |
| [APPRUNNER](reference/apprunner.md) | 1 |
| [APPSTREAM](reference/appstream.md) | 2 |
| [ATHENA](reference/athena.md) | 3 |
| [AUDITMANAGER](reference/auditmanager.md) | 1 |
| [AUTOSCALING](reference/autoscaling.md) | 3 |
| [AZURE](reference/azure.md) | 141 |
| [BACKUP](reference/backup.md) | 13 |
| [BATCH](reference/batch.md) | 3 |
| [BEANSTALK](reference/beanstalk.md) | 3 |
| [BEDROCK](reference/bedrock.md) | 47 |
| [CFN](reference/cfn.md) | 1 |
| [CISCO](reference/cisco.md) | 30 |
| [CLOUD9](reference/cloud9.md) | 2 |
| [CLOUDFLARE](reference/cloudflare.md) | 29 |
| [CLOUDFORMATION](reference/cloudformation.md) | 9 |
| [CLOUDFRONT](reference/cloudfront.md) | 72 |
| [CLOUDTRAIL](reference/cloudtrail.md) | 59 |
| [CLOUDWATCH](reference/cloudwatch.md) | 67 |
| [CODEBUILD](reference/codebuild.md) | 13 |
| [CODECOMMIT](reference/codecommit.md) | 2 |
| [CODEPIPELINE](reference/codepipeline.md) | 5 |
| [COGNITO](reference/cognito.md) | 113 |
| [COMPLIANCE](reference/compliance.md) | 1 |
| [CONFIG](reference/config.md) | 51 |
| [DATACLASS](reference/dataclass.md) | 5 |
| [DATASYNC](reference/datasync.md) | 1 |
| [DMS](reference/dms.md) | 7 |
| [DNS](reference/dns.md) | 3 |
| [DOCUMENTDB](reference/documentdb.md) | 18 |
| [DYNAMODB](reference/dynamodb.md) | 38 |
| [EBS](reference/ebs.md) | 2 |
| [EC2](reference/ec2.md) | 110 |
| [ECR](reference/ecr.md) | 10 |
| [ECS](reference/ecs.md) | 52 |
| [EFS](reference/efs.md) | 14 |
| [EKS](reference/eks.md) | 115 |
| [ELASTICACHE](reference/elasticache.md) | 8 |
| [ELB](reference/elb.md) | 80 |
| [EMR](reference/emr.md) | 6 |
| [EVENTBRIDGE](reference/eventbridge.md) | 97 |
| [EVS](reference/evs.md) | 1 |
| [EXPOSURE](reference/exposure.md) | 11 |
| [FIREHOSE](reference/firehose.md) | 1 |
| [FMS](reference/fms.md) | 2 |
| [GCP](reference/gcp.md) | 72 |
| [GCS](reference/gcs.md) | 7 |
| [GHOST](reference/ghost.md) | 2 |
| [GITHUB](reference/github.md) | 22 |
| [GLACIER](reference/glacier.md) | 2 |
| [GLOBALACCELERATOR](reference/globalaccelerator.md) | 1 |
| [GLUE](reference/glue.md) | 13 |
| [GRAFANA](reference/grafana.md) | 1 |
| [GUARDDUTY](reference/guardduty.md) | 18 |
| [GUARDRAIL](reference/guardrail.md) | 1 |
| [IAM](reference/iam.md) | 304 |
| [INSPECTOR](reference/inspector.md) | 3 |
| [K8S](reference/k8s.md) | 68 |
| [KINESIS](reference/kinesis.md) | 4 |
| [KMS](reference/kms.md) | 47 |
| [LAMBDA](reference/lambda.md) | 91 |
| [LIFECYCLE](reference/lifecycle.md) | 1 |
| [LIGHTSAIL](reference/lightsail.md) | 5 |
| [M365](reference/m365.md) | 73 |
| [MACIE](reference/macie.md) | 4 |
| [MEDIASTORE](reference/mediastore.md) | 1 |
| [META](reference/meta.md) | 1 |
| [MODEL](reference/model.md) | 2 |
| [MQ](reference/mq.md) | 3 |
| [MSK](reference/msk.md) | 9 |
| [MWAA](reference/mwaa.md) | 2 |
| [NEPTUNE](reference/neptune.md) | 20 |
| [NETFIREWALL](reference/netfirewall.md) | 13 |
| [OPENSEARCH](reference/opensearch.md) | 132 |
| [ORG](reference/org.md) | 54 |
| [RAM](reference/ram.md) | 3 |
| [RDS](reference/rds.md) | 72 |
| [RECYCLEBIN](reference/recyclebin.md) | 2 |
| [REDSHIFT](reference/redshift.md) | 26 |
| [ROUTE53](reference/route53.md) | 50 |
| [S3](reference/s3.md) | 148 |
| [S3EXPRESS](reference/s3express.md) | 6 |
| [S3TABLES](reference/s3tables.md) | 3 |
| [S3VECTORS](reference/s3vectors.md) | 3 |
| [SAGEMAKER](reference/sagemaker.md) | 36 |
| [SECRET](reference/secret.md) | 3 |
| [SECRETS](reference/secrets.md) | 31 |
| [SECRETSMANAGER](reference/secretsmanager.md) | 5 |
| [SECURITYHUB](reference/securityhub.md) | 7 |
| [SECURITYLAKE](reference/securitylake.md) | 2 |
| [SERVERLESSREPO](reference/serverlessrepo.md) | 1 |
| [SERVICECATALOG](reference/servicecatalog.md) | 1 |
| [SES](reference/ses.md) | 3 |
| [SHIELD](reference/shield.md) | 6 |
| [SNS](reference/sns.md) | 39 |
| [SQS](reference/sqs.md) | 37 |
| [SSM](reference/ssm.md) | 13 |
| [STEPFUNCTIONS](reference/stepfunctions.md) | 113 |
| [TAGS](reference/tags.md) | 1 |
| [TRANSFER](reference/transfer.md) | 2 |
| [VPC](reference/vpc.md) | 100 |
| [VSPHERE](reference/vsphere.md) | 35 |
| [WAF](reference/waf.md) | 17 |
| [WORKSPACES](reference/workspaces.md) | 1 |
