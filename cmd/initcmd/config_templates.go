package initcmd

import "github.com/sufield/stave/internal/core/kernel"

const templateObservation = `
{
  "schema_version": "` + string(kernel.SchemaObservation) + `",
  "generated_by": {
    "source_type": "aws-s3-snapshot",
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
        }
      }
    }
  ]
}
`
