# Per-bucket public access block, merged into the base bucket asset by id.
#
# INPUT CONTRACT: aws s3api get-public-access-block returns only
# {"PublicAccessBlockConfiguration":{...}} with no bucket name, so the join key
# must be supplied. The collector annotates the call with the bucket name:
#   {"Bucket":"<name>","PublicAccessBlockConfiguration":{...}}
# A file without "Bucket" is not recognized as this filter (it is skipped),
# because there is no id to merge it onto.
#
# Mapping matches scripts/aws-snapshot.sh's public_access_block block.
{
  id: ("arn:aws:s3:::" + .Bucket),
  type: "aws_s3_bucket",
  vendor: "aws",
  properties: { storage: { controls: {
    public_access_block: {
      block_public_acls:       (.PublicAccessBlockConfiguration.BlockPublicAcls       // false),
      block_public_policy:     (.PublicAccessBlockConfiguration.BlockPublicPolicy     // false),
      ignore_public_acls:      (.PublicAccessBlockConfiguration.IgnorePublicAcls      // false),
      restrict_public_buckets: (.PublicAccessBlockConfiguration.RestrictPublicBuckets // false)
    },
    public_access_fully_blocked: (
      (.PublicAccessBlockConfiguration.BlockPublicAcls       // false) and
      (.PublicAccessBlockConfiguration.BlockPublicPolicy     // false) and
      (.PublicAccessBlockConfiguration.IgnorePublicAcls      // false) and
      (.PublicAccessBlockConfiguration.RestrictPublicBuckets // false)
    )
  } } }
}
