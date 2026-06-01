package initcmd

import "github.com/sufield/stave/internal/core/kernel"

// templateObservation is the starter observation file written by
// `stave generate observation`. It includes one asset per common
// type so a new project can run `stave apply` end-to-end without first
// learning the wire format. Real workloads replace this with output
// from an extractor (Steampipe, Terraform State, AWS Config — see
// integrations/).
const templateObservation = `
{
  "schema_version": "` + string(kernel.SchemaObservation) + `",
  "generated_by": {
    "source_type": "stave-template",
    "tool": "stave-template"
  },
  "captured_at": "2026-01-11T00:00:00Z",
  "assets": [
    {
      "id": "aws:s3:::example-phi-bucket",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "access": {
            "public_read": false,
            "public_list": false
          }
        },
        "encryption": {
          "algorithm": "AES256"
        }
      }
    },
    {
      "id": "aws:ec2::us-east-1:i-0123456789abcdef0",
      "type": "aws_ec2_instance",
      "vendor": "aws",
      "properties": {
        "instance_type": "t3.micro",
        "state": "running",
        "public_ip_address": null,
        "metadata_options": {
          "http_tokens": "required",
          "http_endpoint": "enabled"
        }
      }
    },
    {
      "id": "aws:iam::123456789012:role/example-role",
      "type": "aws_iam_role",
      "vendor": "aws",
      "properties": {
        "assume_role_policy": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {"Service": "lambda.amazonaws.com"},
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "attached_policy_arns": []
      }
    }
  ]
}
`
