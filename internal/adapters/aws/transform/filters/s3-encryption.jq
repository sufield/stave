# Per-bucket default encryption, merged into the base bucket asset by id.
#
# INPUT CONTRACT: aws s3api get-bucket-encryption returns
# {"ServerSideEncryptionConfiguration":{...}} with no bucket name, so the
# collector annotates it with the bucket name (the merge key):
#   {"Bucket":"<name>","ServerSideEncryptionConfiguration":{...}}
# A file without "Bucket" is skipped (no id to merge onto).
#
# Mapping matches scripts/aws-snapshot.sh: algorithm/kms_key_id come from the
# first rule's ApplyServerSideEncryptionByDefault; no encryption -> "none"/null.
(.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault // {}) as $enc
| {
  id: ("arn:aws:s3:::" + .Bucket),
  type: "aws_s3_bucket",
  vendor: "aws",
  properties: { storage: { encryption: {
    algorithm: ($enc.SSEAlgorithm // "none"),
    kms_key_id: ($enc.KMSMasterKeyID // null)
  } } }
}
