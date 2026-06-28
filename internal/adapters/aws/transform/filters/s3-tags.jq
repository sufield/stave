# Per-bucket tags, merged into the base bucket asset by id.
#
# INPUT CONTRACT: aws s3api get-bucket-tagging returns {"TagSet":[{Key,Value}]}
# with no bucket name, so the collector annotates it with the bucket name (the
# merge key):
#   {"Bucket":"<name>","TagSet":[{"Key":…,"Value":…}]}
# A file without "Bucket" is skipped (no id to merge onto).
#
# Mapping matches scripts/aws-snapshot.sh: the Key/Value list folded into an
# object. Tag VALUES are hashed by the Go scrubber when the key looks secret.
{
  id: ("arn:aws:s3:::" + .Bucket),
  type: "aws_s3_bucket",
  vendor: "aws",
  properties: { storage: {
    tags: ((.TagSet // []) | map({(.Key): .Value}) | add // {})
  } }
}
